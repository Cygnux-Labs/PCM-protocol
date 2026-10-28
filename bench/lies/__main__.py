"""python -m bench.lies gen | run --verifier tracekit|standalone|baselines|all [--data PATH] | report [--data PATH]"""
import sys


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    cmd, rest = (argv[0], argv[1:]) if argv else ("", [])
    if cmd == "gen":
        from bench.lies import gen   # imports tracekit: only here
        return gen.main()
    if cmd == "run":
        from bench.lies import run
        return run.main(rest)
    if cmd == "report":
        from bench.lies import report
        return report.main(rest)
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
