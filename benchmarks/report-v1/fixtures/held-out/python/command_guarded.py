import subprocess

ALLOWED = {"avatar", "banner"}


def convert(request):
    source = request.args["source"]
    if source not in ALLOWED:
        raise ValueError("unsupported source")
    return subprocess.check_output(["convert", source, "out.png"])
