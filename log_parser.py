#!/usr/bin/env python3

'''Parse directory of access log files and generate statistics report.

Developed and tested on Ubuntu 16.04, Python 3.5.2
by Konstantin Veretennicov <kveretennicov@gmail.com>.
'''

import argparse
import sys
import os
import logging
from collections import namedtuple, Counter
import io
import re
import calendar
import statistics # Note: requires Python 3.4
import json


logger = logging.getLogger(__name__)
LogRecord = namedtuple(
    'LogRecord',
    ['year', 'month', 'language', 'file_name', 'status_code', 'bytes_served'])
LogRecordParseError = namedtuple(
    'LogRecordParseError',
    ['file_path', 'line_number'])
log_record_re = re.compile(
    # Ex: 127.0.0.1 - -
    r'^.+?' \
    # Ex: [01/12/2017:13:44:20 +0000]
    + r' \[\d+/(?P<month>\d+)/(?P<year>\d+).+?\]' \
    # Ex: "GET /Thai/some_\"file_name.flac HTTP/1.1"
    # Note: assuming filenames do not contain spaces; otherwise there is a
    # chance that some unexplored/unhandled edge case exists (though the chance
    # of a bug looks very low).
    + r' \".+? /(?P<language>.+?)/(?P<file_name>.+?) .+\"' \
    + r' (?P<status_code>\d+)' \
    + r' (?P<bytes_served>\d+)$')

def _gen_file_log_records(log_file_path):
    '''Parse lines of a single log file into log records or parse errors.
    '''
    with io.open(log_file_path, 'r', encoding='utf8') as f:
        for line_number, line in enumerate(f):
            m = log_record_re.match(line)
            if not m:
                yield LogRecordParseError(
                    file_path=log_file_path,
                    line_number=line_number)
                continue
            try:
                year = int(m.group('year'))
                month = int(m.group('month'))
                status_code = int(m.group('status_code'))
                bytes_served = int(m.group('bytes_served'))
                language = m.group('language')
                escaped_file_name = m.group('file_name')
                file_name = escaped_file_name \
                    .replace('\\"', '"').replace('\\\\', '\\')
            except:
                yield LogRecordParseError(
                    file_path=log_file_path,
                    line_number=line_number)
                continue
            yield LogRecord(
                year=year,
                month=month,
                # Note: language names are not canonicalized;
                # use lower() or something else if required
                language=language,
                # Note: assuming file names are case-sensitive
                file_name=file_name,
                status_code=status_code,
                bytes_served=bytes_served)

def _gen_dir_log_records(log_dir_path):
    '''Parse lines of all log files from a directory into log records or errors.
    '''
    for name in os.listdir(log_dir_path):
        path = os.path.join(log_dir_path, name)
        if not os.path.isfile(path):
            logger.warning('"%s" is not a file, skipping', path)
            continue
        try:
            yield from _gen_file_log_records(path)
        except:
            logger.warning('"%s" cannot be parsed, skipping', path)

def _format_month(month_number):
    # Note: returns localized month name;
    # use fixed locale or hardcode month list if English names are required
    return calendar.month_name[month_number]

def _get_stats(log_records):
    '''Collect statistics from a sequence of log records.
    '''
    # Note: expecting accumulators to be small enough even for large sets
    # of logs, so keeping everything in memory. For certain data this assumption
    # may be broken, which may require more complex design involving disk
    # persistence for some or all data. Main factors that may blow up the memory
    # usage is the number of distinct languages, file names and non-ASCII file
    # names.
    # Note: if log records came in chronological order, it would be possible
    # to discard accumulated month data and compute its statistics once we've
    # reached the next month. This could reduce somewhat the memory pressure.
    # The test data, however, is not ordered chronologically.
    months = {}
    for request in log_records:
        month_date = (request.year, request.month)
        is_successful_request = request.status_code // 100 == 2 # 2xx
        month_data = months.get(month_date)
        if month_data is None:
            months[month_date] = month_data = {
                'year': str(request.year),
                'month': _format_month(request.month),
                'languages': {},
                'non_ascii': set(),
                'requests': {
                    'total': 0,
                    'success': 0,
                    'percent_success': None,
                }
            }
        month_langs = month_data['languages']
        lang_data = month_langs.get(request.language)
        if lang_data is None:
            month_langs[request.language] = lang_data = {
                'name': request.language,
                'mean_MB': None,
                'stddev_MB': None,
                'total_GB': None, # Only from 2xx
                '_total_successful_B': 0,
                '_total_successful': 0,
                # Note: Counter wins over list when there are many repeated
                # values.
                '_bytes_served_successfully': Counter(),
            }
        # Collect non-ASCII names.
        if any(ord(ch) > 127 for ch in request.file_name):
            month_data['non_ascii'].add(request.file_name)
        # Track request successes/failures.
        month_requests = month_data['requests']
        month_requests['total'] += 1
        if is_successful_request:
            month_requests['success'] += 1
        # Track successful requests traffic.
        if is_successful_request:
            lang_data['_total_successful'] += 1
            lang_data['_total_successful_B'] += request.bytes_served
            lang_data['_bytes_served_successfully'][request.bytes_served] += 1
    # Finally, list months in chronological order.
    return [months[month_date] for month_date in sorted(months)]

def _gen_filter_errors(log_records_or_errors):
    '''Report log parse errors and filter them out of the sequence.
    '''
    for log_record_or_error in log_records_or_errors:
        if isinstance(log_record_or_error, LogRecordParseError):
            error = log_record_or_error
            logger.warning(
                'line %d of "%s" cannot be parsed, skipping',
                error.line_number, error.file_path)
        else:
            assert isinstance(log_record_or_error, LogRecord)
            record = log_record_or_error
            yield record

def _reshape_stats(stats, top_count=5):
    '''Compute aggregates and update stats to comply with the output format.
    '''
    mb = 1000 * 1000
    gb = 1000 * 1000 * 1000
    for month_data in stats:
        # Fill in monthly requests' success percentage.
        month_requests = month_data['requests']
        assert month_requests['total'] != 0 # Should be true by construction.
        month_requests['percent_success'] = \
            month_requests['success'] * 100 / month_requests['total']
        # Shape non-ASCII name set into list (json doesn't like sets).
        month_data['non_ascii'] = list(month_data['non_ascii'])
        # Shape language stats.
        month_langs = month_data['languages']
        reshaped_month_langs = sorted(
            month_langs.values(),
            key=lambda ml: ml['_total_successful_B'],
            reverse=True)
        del reshaped_month_langs[top_count:]
        # Fill in per-language traffic statistics.
        for lang_data in reshaped_month_langs:
            lang_data['total_GB'] = lang_data['_total_successful_B'] / gb
            n = lang_data['_total_successful']
            if n:
                pop_mean = lang_data['_total_successful_B'] / n / mb
                # Note: using pstdev assuming that logs are the full dataset
                # and not a sample.
                pop_stdev = statistics.pstdev(
                    (bytes_served / mb
                        for bytes_served
                        in lang_data['_bytes_served_successfully'].elements()),
                    mu=pop_mean)
            else:
                # Empty dataset -> statistics is not defined.
                pop_mean = None
                pop_stdev = None
            lang_data['mean_MB'] = pop_mean
            lang_data['stddev_MB'] = pop_stdev
            # Remove temp keys.
            for key in list(lang_data):
                if key[:1] == '_':
                    del lang_data[key]
        month_data['languages'] = reshaped_month_langs

def main(log_dir_path, report_file_path):
    try:
        log_records = _gen_filter_errors(_gen_dir_log_records(log_dir_path))
        stats = _get_stats(log_records)
        _reshape_stats(stats)
        f, release_f = (sys.stdout, lambda: None) if report_file_path == '-' \
            else (io.open(report_file_path, 'w', encoding='utf8'), f.close)
        try:
            json.dump(stats, f, indent=' ' * 2, sort_keys=True)
        finally:
            release_f()
        return 0
    except Exception:
        logger.exception('unexpected error')
        return -1

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Generate report from access logs.')
    parser.add_argument(
        'input_dir_path',
        help='path to the directory with log files to be read')
    parser.add_argument(
        'output_file_path',
        help='path to the JSON report file to be created; use "-" for stdout')
    args = parser.parse_args()
    r = main(args.input_dir_path, args.output_file_path)
    sys.exit(r)
