import subprocess


def convert(request):
    source = request.args["source"]
    return subprocess.check_output(["sh", "-c", f"convert {source} out.png"])
