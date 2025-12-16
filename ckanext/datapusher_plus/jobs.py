```python
# -*- coding: utf-8 -*-
# flake8: noqa: E501

# Standard library imports
import csv
import hashlib
import locale
import mimetypes
import os
import subprocess
import tempfile
import time
from urllib.parse import urlsplit, urlparse
import logging
import uuid
import sys
import json
import requests
from pathlib import Path
from typing import Dict, Any, Optional, List

# Third-party imports
import psycopg2
from psycopg2 import sql
from datasize import DataSize
from dateutil.parser import parse as parsedate
import traceback
import sqlalchemy as sa
from rq import get_current_job
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager

import ckanext.datapusher_plus.utils as utils
import ckanext.datapusher_plus.helpers as dph
import ckanext.datapusher_plus.jinja2_helpers as j2h
from ckanext.datapusher_plus.job_exceptions import HTTPError
import ckanext.datapusher_plus.config as conf
import ckanext.datapusher_plus.spatial_helpers as sh
import ckanext.datapusher_plus.datastore_utils as dsu
from ckanext.datapusher_plus.logging_utils import TRACE
from ckanext.datapusher_plus.qsv_utils import QSVCommand
from ckanext.datapusher_plus.pii_screening import screen_for_pii

if locale.getdefaultlocale()[0]:
    lang, encoding = locale.getdefaultlocale()
    locale.setlocale(locale.LC_ALL, locale=(lang, encoding))
else:
    locale.setlocale(locale.LC_ALL, "")

class TLS12CompatAdapter(HTTPAdapter):
    """
    Force TLSv1.2 + relaxed cipher security level for a small set of problematic servers.
    Applied only when we explicitly mount this adapter onto a per-download Session.
    """

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers(conf.DOWNLOAD_TLS12_COMPAT_CIPHERS)

        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=ctx,
            **pool_kwargs,
        )


def validate_input(input: Dict[str, Any]) -> None:
    # Especially validate metadata which is provided by the user
    if "metadata" not in input:
        raise utils.JobError("Metadata missing")

    data = input["metadata"]

    if "resource_id" not in data:
        raise utils.JobError("No id provided.")


def callback_datapusher_hook(result_url: str, job_dict: Dict[str, Any]) -> bool:
    api_token = utils.get_dp_plus_user_apitoken()
    headers: Dict[str, str] = {
        "Content-Type": "application/json",
        "Authorization": api_token,
    }

    try:
        result = requests.post(
            result_url,
            data=json.dumps(job_dict, cls=utils.DatetimeJsonEncoder),
            verify=conf.SSL_VERIFY,
            headers=headers,
        )
    except requests.ConnectionError:
        return False

    return result.status_code == requests.codes.ok


def datapusher_plus_to_datastore(input: Dict[str, Any]) -> Optional[str]:
    """
    This is the main function that is called by the datapusher_plus worker

    Errors are caught and logged in the database

    Args:
        input: Dictionary containing metadata and other job information

    Returns:
        Optional[str]: Returns "error" if there was an error, None otherwise
    """
    job_dict: Dict[str, Any] = dict(metadata=input["metadata"], status="running")
    callback_datapusher_hook(result_url=input["result_url"], job_dict=job_dict)

    job_id = get_current_job().id
    errored = False
    try:
        push_to_datastore(input, job_id)
        job_dict["status"] = "complete"
        dph.mark_job_as_completed(job_id, job_dict)
    except utils.JobError as e:
        dph.mark_job_as_errored(job_id, str(e))
        job_dict["status"] = "error"
        job_dict["error"] = str(e)
        log = logging.getLogger(__name__)
        log.error(f"Datapusher Plus error: {e}, {traceback.format_exc()}")
        errored = True
    except Exception as e:
        dph.mark_job_as_errored(
            job_id, traceback.format_tb(sys.exc_info()[2])[-1] + repr(e)
        )
        job_dict["status"] = "error"
        job_dict["error"] = str(e)
        log = logging.getLogger(__name__)
        log.error(f"Datapusher Plus error: {e}, {traceback.format_exc()}")
        errored = True
    finally:
        # job_dict is defined in datapusher_hook's docstring
        is_saved_ok = callback_datapusher_hook(
            result_url=input["result_url"], job_dict=job_dict
        )
        errored = errored or not is_saved_ok
    return "error" if errored else None


def push_to_datastore(
    input: Dict[str, Any], task_id: str, dry_run: bool = False
) -> Optional[List[Dict[str, Any]]]:
    """Download and parse a resource push its data into CKAN's DataStore.

    An asynchronous job that gets a resource from CKAN, downloads the
    resource's data file and, if the data file has changed since last time,
    parses the data and posts it into CKAN's DataStore.

    Args:
        input: Dictionary containing metadata and other job information
        task_id: Unique identifier for the task
        dry_run: If True, fetch and parse the data file but don't actually post the
            data to the DataStore, instead return the data headers and rows that
            would have been posted.

    Returns:
        Optional[List[Dict[str, Any]]]: If dry_run is True, returns the headers and rows
            that would have been posted. Otherwise returns None.
    """
    # Ensure temporary files are removed after run
    with tempfile.TemporaryDirectory() as temp_dir:
        return _push_to_datastore(task_id, input, dry_run=dry_run, temp_dir=temp_dir)

def _download_session_for_resource(resource: Dict[str, Any]) -> requests.Session:
    s = requests.Session()
    if conf.DOWNLOAD_TLS12_COMPAT_ENABLED and resource.get("url_type") != "upload":
        s.mount("https://", TLS12CompatAdapter())
    return s

def _push_to_datastore(
    task_id: str,
    input: Dict[str, Any],
    dry_run: bool = False,
    temp_dir: Optional[str] = None,
) -> Optional[List[Dict[str, Any]]]:
    # add job to dn  (datapusher_plus_jobs table)
    try:
        dph.add_pending_job(task_id, **input)
    except sa.exc.IntegrityError:
        raise utils.JobError("Job already exists.")
    handler = utils.StoringHandler(task_id, input)
    logger = logging.getLogger(task_id)
    logger.addHandler(handler)

    # also show logs on stderr
    logger.addHandler(logging.StreamHandler())

    # set the log level to the config upload_log_level
    try:
        log_level = getattr(logging, conf.UPLOAD_LOG_LEVEL.upper())
    except AttributeError:
        # fallback to our custom TRACE level
        log_level = TRACE

    # set the log level to the config upload_log_level
    logger.setLevel(logging.INFO)
    logger.info(f"Setting log level to {logging.getLevelName(int(log_level))}")
    logger.setLevel(log_level)

    # check if conf.QSV_BIN exists
    if not Path(conf.QSV_BIN).is_file():
        raise utils.JobError(f"{conf.QSV_BIN} not found.")

    # Initialize QSVCommand
    qsv = QSVCommand(logger=logger)

    validate_input(input)

    data = input["metadata"]

    ckan_url = data["ckan_url"]
    resource_id = data["resource_id"]
    try:
        resource = dsu.get_resource(resource_id)
    except utils.JobError:
        # try again in 5 seconds just incase CKAN is slow at adding resource
        time.sleep(5)
        resource = dsu.get_resource(resource_id)

    # check if the resource url_type is a datastore
    if resource.get("url_type") == "datastore":
        logger.info("Dump files are managed with the Datastore API")
        return

    # check scheme
    resource_url = resource.get("url")
    scheme = urlsplit(resource_url).scheme
    if scheme not in ("http", "https", "ftp"):
        raise utils.JobError("Only http, https, and ftp resources may be fetched.")

    # ==========================================================================
    # DOWNLOAD
    # ==========================================================================
    timer_start = time.perf_counter()
    dataset_stats = {}

    # fetch the resource data
    logger.info(f"Fetching from: {resource_url}...")
    headers: Dict[str, str] = {}
    if resource.get("url_type") == "upload":
        # If this is an uploaded file to CKAN, authenticate the request,
        # otherwise we won't get file from private resources
        api_token = utils.get_dp_plus_user_apitoken()
        headers["Authorization"] = api_token

        # If the ckan_url differs from this url, rewrite this url to the ckan
        # url. This can be useful if ckan is behind a firewall.
        if not resource_url.startswith(ckan_url):
            new_url = urlparse(resource_url)
            rewrite_url = urlparse(ckan_url)
            new_url = new_url._replace(
                scheme=rewrite_url.scheme, netloc=rewrite_url.netloc
            )
            resource_url = new_url.geturl()
            logger.info(f"Rewritten resource url to: {resource_url}")

    try:
        kwargs: Dict[str, Any] = {
            "headers": headers,
            "timeout": conf.TIMEOUT,
            "verify": conf.SSL_VERIFY,
            "stream": True,
        }
        if conf.USE_PROXY:
            kwargs["proxies"] = {
                "http": conf.DOWNLOAD_PROXY,
                "https": conf.DOWNLOAD_PROXY,
            }

        # CHANGED: create a per-download session so we can mount TLS1.2 workaround only here
        session = _download_session_for_resource(resource)
        try:
            # CHANGED: use session.get(...) instead of requests.get(...)
            with session.get(resource_url, **kwargs) as response:
                response.raise_for_status()

                cl = response.headers.get("content-length")
                max_content_length = conf.MAX_CONTENT_LENGTH
                ct = response.headers.get("content-type")

                try:
                    if cl and int(cl) > max_content_length and conf.PREVIEW_ROWS > 0:
                        raise utils.JobError(
                            f"Resource too large to download: {DataSize(int(cl)):.2MB} > max ({DataSize(int(max_content_length)):.2MB})."
                        )
                except ValueError:
                    pass

                resource_format = resource.get("format").upper()

                # if format was not specified, try to get it from mime type
                if not resource_format:
                    logger.info("File format: NOT SPECIFIED")
                    # if we have a mime type, get the file extension from the response header
                    if ct:
                        resource_format = mimetypes.guess_extension(ct.split(";")[0])

                        if resource_format is None:
                            raise utils.JobError(
                                "Cannot determine format from mime type. Please specify format."
                            )
                        logger.info(f"Inferred file format: {resource_format}")
                    else:
                        raise utils.JobError(
                            "Server did not return content-type. Please specify format."
                        )
                else:
                    logger.info(f"File format: {resource_format}")

                tmp = os.path.join(temp_dir, "tmp." + resource_format)
                length = 0
                # using MD5 for file deduplication only
                # no need for it to be cryptographically secure
                m = hashlib.md5()  # DevSkim: ignore DS126858

                # download the file
                if cl:
                    logger.info(f"Downloading {DataSize(int(cl)):.2MB} file...")
                else:
                    logger.info("Downloading file of unknown size...")

                with open(tmp, "wb") as tmp_file:
                    for chunk in response.iter_content(conf.CHUNK_SIZE):
                        length += len(chunk)
                        if length > max_content_length and not conf.PREVIEW_ROWS:
                            raise utils.JobError(
                                f"Resource too large to process: {length} > max ({max_content_length})."
                            )
                        tmp_file.write(chunk)
                        m.update(chunk)
        finally:
            # ADDED: close the session to avoid keeping sockets around in long-running workers
            session.close()

    except requests.HTTPError as e:
        raise HTTPError(
            f"DataPusher+ received a bad HTTP response when trying to download "
            f"the data file from {resource_url}. Status code: {e.response.status_code}, "
            f"Response content: {e.response.content}",
            status_code=e.response.status_code,
            request_url=resource_url,
            response=e.response.content,
        )
    except requests.RequestException as e:
        raise HTTPError(
            message=str(e),
            status_code=None,
            request_url=resource_url,
            response=None,
        )

    file_hash = m.hexdigest()
    dataset_stats["ORIGINAL_FILE_SIZE"] = length

    # check if the resource metadata (like data dictionary data types)
    # has been updated since the last fetch
    resource_updated = False
    resource_last_modified = resource.get("last_modified")
    if resource_last_modified:
        resource_last_modified = parsedate(resource_last_modified)
        file_last_modified = response.headers.get("last-modified")
        if file_last_modified:
            file_last_modified = parsedate(file_last_modified).replace(tzinfo=None)
            if file_last_modified < resource_last_modified:
                resource_updated = True

    if (
        resource.get("hash") == file_hash
        and not data.get("ignore_hash")
        and not conf.IGNORE_FILE_HASH
        and not resource_updated
    ):
        logger.warning(f"Upload skipped as the file hash hasn't changed: {file_hash}.")
        return

    resource["hash"] = file_hash

    fetch_elapsed = time.perf_counter() - timer_start
    logger.info(
        f"Fetched {DataSize(length):.2MB} file in {fetch_elapsed:,.2f} seconds."
    )

    # Check if the file is a zip file
    unzipped_format = ""
    if resource_format.upper() == "ZIP":
        logger.info("Processing ZIP file...")

        file_count, extracted_path, unzipped_format = dph.extract_zip_or_metadata(
            tmp, temp_dir, logger
        )
        if not file_count:
            logger.error("ZIP file invalid or no files found in ZIP file.")
            return
        logger.info(
            f"More than one file in the ZIP file ({file_count} files), saving metadata..."
            if file_count > 1
            else f"Extracted {unzipped_format} file: {extracted_path}"
        )
        tmp = extracted_path

    # ===================================================================================
    # ANALYZE WITH QSV
    # ===================================================================================
    # Start Analysis using qsv instead of messytables, as
    # 1) its type inferences are bullet-proof not guesses as it scans the entire file,
    # 2) its super-fast, and
    # 3) it has addl data-wrangling capabilities we use in DP+ (e.g. stats, dedup, etc.)
    dupe_count = 0
    record_count = 0
    analysis_start = time.perf_counter()
    logger.info("ANALYZING WITH QSV..")

    # flag to check if the file is a spatial format
    spatial_format_flag = False
    simplification_failed_flag = False
    # ----------------- is it a spreadsheet? ---------------
    # check content type or file extension if its a spreadsheet
    spreadsheet_extensions = ["XLS", "XLSX", "ODS", "XLSM", "XLSB"]
    file_format = resource.get("format").upper()
    if (
        file_format in spreadsheet_extensions
        or unzipped_format in spreadsheet_extensions
    ):
        # if so, export spreadsheet as a CSV file
        default_excel_sheet = conf.DEFAULT_EXCEL_SHEET
        file_format = unzipped_format if unzipped_format != "" else file_format
        logger.info(f"Converting {file_format} sheet {default_excel_sheet} to CSV...")
        # first, we need a temporary spreadsheet filename with the right file extension
        # we only need the filename though, that's why we remove it
        # and create a hardlink to the file we got from CKAN
        qsv_spreadsheet = os.path.join(temp_dir, "qsv_spreadsheet." + file_format)
        os.link(tmp, qsv_spreadsheet)

        # run `qsv excel` and export it to a CSV
        # use --trim option to trim column names and the data
        qsv_excel_csv = os.path.join(temp_dir, "qsv_excel.csv")
        try:
            qsv_excel = qsv.excel(
                qsv_spreadsheet,
                sheet=default_excel_sheet,
                trim=True,
                output_file=qsv_excel_csv,
            )
        except utils.JobError as e:
            raise utils.JobError(
                f"Upload aborted. Cannot export spreadsheet(?) to CSV: {e}"
            )
        excel_export_msg = qsv_excel.stderr
        logger.info(f"{excel_export_msg}...")
        tmp = qsv_excel_csv
    elif resource_format.upper() in ["SHP", "QGIS", "GEOJSON"]:
        logger.info("SHAPEFILE or GEOJSON file detected...")

        qsv_spatial_file = os.path.join(
            temp_dir,
            "qsv_spatial_" + str(uuid.uuid4()) + "." + resource_format,
        )
        os.link(tmp, qsv_spatial_file)
        qsv_spatial_csv = os.path.join(temp_dir, "qsv_spatial.csv")

        if conf.AUTO_SPATIAL_SIMPLIFICATION:
            # Try to convert spatial file to CSV using spatial_helpers
            logger.info(
                f"Converting spatial file to CSV with a simplification relative tolerance of {conf.SPATIAL_SIMPLIFICATION_RELATIVE_TOLERANCE}..."
            )

            try:
                # Use the convert_to_csv function from spatial_helpers
                success, error_message, bounds = sh.process_spatial_file(
                    qsv_spatial_file,
                    resource_format,
                    output_csv_path=qsv_spatial_csv,
                    tolerance=conf.SPATIAL_SIMPLIFICATION_RELATIVE_TOLERANCE,
                    task_logger=logger,
                )

                if success:
                    logger.info(
                        "Spatial file successfully simplified and converted to CSV"
                    )
                    tmp = qsv_spatial_csv

                    # Check if the simplified resource already exists
                    simplified_resource_name = (
                        os.path.splitext(resource["name"])[0]
                        + "_simplified"
                        + os.path.splitext(resource["name"])[1]
                    )
                    existing_resource, existing_resource_id = dsu.resource_exists(
                        resource["package_id"], simplified_resource_name
                    )

                    if existing_resource:
                        logger.info(
                            "Simplified resource already exists. Replacing it..."
                        )
                        dsu.delete_resource(existing_resource_id)
                    else:
                        logger.info(
                            "Simplified resource does not exist. Uploading it..."
                        )
                        new_simplified_resource = {
                            "package_id": resource["package_id"],
                            "name": os.path.splitext(resource["name"])[0]
                            + "_simplified"
                            + os.path.splitext(resource["name"])[1],
                            "url": "",
                            "format": resource["format"],
                            "hash": "",
                            "mimetype": resource["mimetype"],
                            "mimetype_inner": resource["mimetype_inner"],
                        }

                        # Add bounds information if available
                        if bounds:
                            minx, miny, maxx, maxy = bounds
                            new_simplified_resource.update(
                                {
                                    "dpp_spatial_extent": {
                                        "type": "BoundingBox",
                                        "coordinates": [
                                            [minx, miny],
                                            [maxx, maxy],
                                        ],
                                    }
                                }
                            )
                            logger.info(
                                f"Added dpp_spatial_extent to resource metadata: {bounds}"
                            )

                        dsu.upload_resource(new_simplified_resource, qsv_spatial_file)

                        # delete the simplified spatial file
                        os.remove(qsv_spatial_file)

                    simplification_failed_flag = False
                else:
                    logger.warning(
                        f"Upload of simplified spatial file failed: {error_message}"
                    )
                    simplification_failed_flag = True
            except Exception as e:
                logger.warning(f"Simplification and conversion failed: {str(e)}")
                logger.warning(
                    f"Simplification and conversion failed. Using qsv geoconvert to convert to CSV, truncating large columns to {conf.QSV_STATS_STRING_MAX_LENGTH} characters..."
                )
                simplification_failed_flag = True
                pass

        # If we are not auto-simplifying or simplification failed, use qsv geoconvert
        if not conf.AUTO_SPATIAL_SIMPLIFICATION or simplification_failed_flag:
            logger.info("Converting spatial file to CSV using qsv geoconvert...")

            # Run qsv geoconvert
            qsv_geoconvert_csv = os.path.join(temp_dir, "qsv_geoconvert.csv")
            try:
                qsv.geoconvert(
                    tmp,
                    resource_format,
                    "csv",
                    max_length=conf.QSV_STATS_STRING_MAX_LENGTH,
                    output_file=qsv_geoconvert_csv,
                )
            except utils.JobError as e:
                raise utils.JobError(f"qsv geoconvert failed: {e}")

            tmp = qsv_geoconvert_csv
            logger.info("Geoconverted successfully")

    else:
        # --- its not a spreadsheet nor a spatial format, its a CSV/TSV/TAB file ------
        # Normalize & transcode to UTF-8 using `qsv input`. We need to normalize as
        # it could be a CSV/TSV/TAB dialect with differing delimiters, quoting, etc.
        # Using qsv input's --output option also auto-transcodes to UTF-8.
        # Note that we only change the workfile, the resource file itself is unchanged.

        # ------------------- Normalize to CSV ---------------------
        qsv_input_csv = os.path.join(temp_dir, "qsv_input.csv")
        # if resource_format is CSV we don't need to normalize
        if resource_format.upper() == "CSV":
            logger.info(f"Normalizing/UTF-8 transcoding {resource_format}...")
        else:
            # if not CSV (e.g. TSV, TAB, etc.) we need to normalize to CSV
            logger.info(f"Normalizing/UTF-8 transcoding {resource_format} to CSV...")

        qsv_input_utf_8_encoded_csv = os.path.join(
            temp_dir, "qsv_input_utf_8_encoded.csv"
        )

        # using uchardet to determine encoding
        file_encoding = subprocess.run(
            ["uchardet", tmp],
            check=True,
            capture_output=True,
            text=True,
        )
        logger.info(f"Identified encoding of the file: {file_encoding.stdout}")

        # trim the encoding string
        file_encoding.stdout = file_encoding.stdout.strip()

        # using iconv to re-encode in UTF-8 OR ASCII (as ASCII is a subset of UTF-8)
        if file_encoding.stdout != "UTF-8" and file_encoding.stdout != "ASCII":
            logger.info(
                f"File is not UTF-8 encoded. Re-encoding from {file_encoding.stdout} to UTF-8"
            )
            try:
                cmd = subprocess.run(
                    [
                        "iconv",
                        "-f",
                        file_encoding.stdout,
                        "-t",
                        "UTF-8",
                        tmp,
                    ],
                    capture_output=True,
                    check=True,
                )
            except subprocess.CalledProcessError as e:
                raise utils.JobError(
                    f"Job aborted as the file cannot be re-encoded to UTF-8. {e.stderr}"
                )
            f = open(qsv_input_utf_8_encoded_csv, "wb")
            f.write(cmd.stdout)
            f.close()
            logger.info("Successfully re-encoded to UTF-8")

        else:
            qsv_input_utf_8_encoded_csv = tmp
        try:
            qsv.input(tmp, trim_headers=True, output_file=qsv_input_csv)
        except utils.JobError as e:
            raise utils.JobError(
                f"Job aborted as the file cannot be normalized/transcoded: {e}."
            )
        tmp = qsv_input_csv
        logger.info("Normalized & transcoded...")

    # ------------------------------------- Validate CSV --------------------------------------
    # Run an RFC4180 check with `qsv validate` against the normalized, UTF-8 encoded CSV file.
    # Even excel exported CSVs can be potentially invalid, as it allows the export of "flexible"
    # CSVs - i.e. rows may have different column counts.
    # If it passes validation, we can handle it with confidence downstream as a "normal" CSV.
    logger.info("Validating CSV...")
    try:
        qsv.validate(tmp)
    except utils.JobError as e:
        raise utils.JobError(f"qsv validate failed: {e}")

    logger.info("Well-formed, valid CSV file confirmed...")

    # --------------------- Sortcheck --------------------------
    # if SORT_AND_DUPE_CHECK is True or DEDUP is True
    # check if the file is sorted and if it has duplicates
    # get the record count, unsorted breaks and duplicate count as well
    if conf.SORT_AND_DUPE_CHECK or conf.DEDUP:
        logger.info("Checking for duplicates and if the CSV is sorted...")

        try:
            qsv_sortcheck = qsv.sortcheck(tmp, json_output=True, uses_stdio=True)
        except utils.JobError as e:
            raise utils.JobError(
                f"Failed to check if CSV is sorted and has duplicates: {e}"
            )

        try:
            # Handle both subprocess.CompletedProcess and dict outputs
            stdout_content = (
                qsv_sortcheck.stdout
                if hasattr(qsv_sortcheck, "stdout")
                else qsv_sortcheck.get("stdout")
            )
            sortcheck_json = json.loads(str(stdout_content))
        except (json.JSONDecodeError, AttributeError) as e:
            raise utils.JobError(f"Failed to parse sortcheck JSONoutput: {e}")

        try:
            # Extract and validate required fields
            is_sorted = bool(sortcheck_json.get("sorted", False))
            record_count = int(sortcheck_json.get("record_count", 0))
            unsorted_breaks = int(sortcheck_json.get("unsorted_breaks", 0))
            dupe_count = int(sortcheck_json.get("dupe_count", 0))
            dataset_stats["IS_SORTED"] = is_sorted
            dataset_stats["RECORD_COUNT"] = record_count
            dataset_stats["UNSORTED_BREAKS"] = unsorted_breaks
            dataset_stats["DUPE_COUNT"] = dupe_count
        except (ValueError, TypeError) as e:
            raise utils.JobError(f"Invalid numeric value in sortcheck output: {e}")

        # Format the message with clear statistics
        sortcheck_msg = f"Sorted: {is_sorted}; Unsorted breaks: {unsorted_breaks:,}"
        if is_sorted and dupe_count > 0:
            sortcheck_msg = f"{sortcheck_msg}; Duplicates: {dupe_count:,}"

        logger.info(sortcheck_msg)

    # --------------- Do we need to dedup? ------------------
    if conf.DEDUP and dupe_count > 0:
        qsv_dedup_csv = os.path.join(temp_dir, "qsv_dedup.csv")
        logger.info(f"{dupe_count} duplicate rows found. Deduping...")

        try:
            qsv.extdedup(tmp, qsv_dedup_csv)
        except utils.JobError as e:
            raise utils.JobError(f"Check for duplicates error: {e}")

        dataset_stats["DEDUPED"] = True
        tmp = qsv_dedup_csv
        logger.info(f"Deduped CSV saved to {qsv_dedup_csv}")
    else:
        dataset_stats["DEDUPED"] = False

    # ----------------------- Headers & Safenames ---------------------------
    # get existing header names, so we can use them for data dictionary labels
    # should we need to change the column name to make it "db-safe"
    try:
        qsv_headers = qsv.headers(tmp, just_names=True)
    except utils.JobError as e:
        raise utils.JobError(f"Cannot scan CSV headers: {e}")
    original_headers = str(qsv_headers.stdout).strip()
    original_header_dict = {
        idx: ele for idx, ele in enumerate(original_headers.splitlines())
    }

    # now, ensure our column/header names identifiers are "safe names"
    # i.e. valid postgres/CKAN Datastore identifiers
    qsv_safenames_csv = os.path.join(temp_dir, "qsv_safenames.csv")
    logger.info('Checking for "database-safe" header names...')
    try:
        qsv_safenames = qsv.safenames(
            tmp,
            mode="json",
            reserved=conf.RESERVED_COLNAMES,
            prefix=conf.UNSAFE_PREFIX,
            uses_stdio=True,
        )
    except utils.JobError as e:
        raise utils.JobError(f"Cannot scan CSV headers: {e}")

    unsafe_json = json.loads(str(qsv_safenames.stdout))
    unsafe_headers = unsafe_json["unsafe_headers"]

    if unsafe_headers:
        logger.info(
            f'"{len(unsafe_headers)} unsafe" header names found ({unsafe_headers}). Sanitizing..."'
        )
        qsv_safenames = qsv.safenames(
            tmp, mode="conditional", output_file=qsv_safenames_csv
        )
        tmp = qsv_safenames_csv
    else:
        logger.info("No unsafe header names found...")

    # ---------------------- Type Inferencing -----------------------
    # at this stage, we have a "clean" CSV ready for Type Inferencing

    # first, index csv for speed - count, stats and slice
    # are all accelerated/multithreaded when an index is present
    try:
        qsv_index_file = tmp + ".idx"
        qsv.index(tmp)
    except utils.JobError as e:
        raise utils.JobError(f"Cannot index CSV: {e}")

    # if SORT_AND_DUPE_CHECK = True, we already know the record count
    # so we can skip qsv count.
    if not conf.SORT_AND_DUPE_CHECK:
        # get record count, this is instantaneous with an index
        try:
            qsv_count = qsv.count(tmp)
            record_count = int
