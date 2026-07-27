def describe(request):
    requested_label = request.args["label"]
    return {"requested": requested_label, "runner": "subprocess.check_output"}
