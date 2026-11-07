#!/usr/bin/env python3
"""Prepare/verify nonpublishing native candidates. Real builds require CI authority."""
import argparse
import json
import os
from pathlib import Path
import sys
from native_validation import common as C


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['build', 'smoke', 'aggregate'])
    parser.add_argument('--target', choices=list(C.TARGETS))
    parser.add_argument('--expected-revision', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--job-result', choices=['success', 'failure', 'cancelled', 'skipped'])
    args = parser.parse_args()
    if args.operation != 'aggregate' and not args.target or args.operation == 'aggregate' and not all((args.directory, args.job_result)):
        parser.error('build/smoke require target; aggregate requires directory and job-result')
    root, output = Path.cwd().resolve(), args.output.resolve()
    if output.is_relative_to(root):
        parser.error('candidate output must be outside source worktree')
    try:
        output.mkdir(mode=0o700, parents=True, exist_ok=args.operation == 'smoke')
    except OSError:
        print(json.dumps({'state': 'failed', 'error': 'output_refused'}))
        return 1
    return execute(args, root, output)


def execute(args, root, output):
    try:
        if args.operation == 'aggregate':
            from native_validation.artifacts import aggregate
            result = aggregate(root, args.directory.resolve(), output, args.expected_revision, args.job_result)
        else:
            from native_validation import build, smoke
            result = getattr({'build': build, 'smoke': smoke}[args.operation], args.operation)(
                root, output, args.target, args.expected_revision)
    except (ValueError, OSError, KeyError, TypeError) as error:
        code = str(error) if type(error) is ValueError else 'input_or_process_refused'
        if not code.replace('_', '').isalnum() or len(code) > 80:
            code = 'input_or_process_refused'
        result = {'state': 'failed', 'stage': args.operation, 'error': code}
        try:
            C.write(output / ('failure-' + (args.target or 'aggregate') + '.json'), result)
        except OSError:
            result['receipt'] = 'unavailable'
        print(json.dumps(result))
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    os.umask(0o077)
    raise SystemExit(main())
