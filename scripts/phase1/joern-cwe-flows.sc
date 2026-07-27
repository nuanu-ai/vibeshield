import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._
import java.nio.charset.StandardCharsets
import java.nio.file.{Files, Paths}
import java.util.Base64

@main def main(cpgFile: String, outFile: String) = {
  importCpg(cpgFile, enhance = true)

  def enc(value: String): String =
    Base64.getEncoder.encodeToString(Option(value).getOrElse("").getBytes(StandardCharsets.UTF_8))

  def sourceCalls = cpg.call.filter { call =>
    val identity = s"${call.name} ${call.methodFullName}".toLowerCase
    val code = call.code.toLowerCase
    val servletSource = Seq(
      "getparameter", "getheader", "getquerystring", "getcookies"
    ).exists(identity.contains) || code.contains("request.getinputstream")
    val pythonSource = Seq(
      "request.args", "request.form", "request.values", "request.json", "request.headers",
      "request.cookies", "request.path", "request.files", "sys.argv", "os.environ"
    ).exists(code.contains)
    servletSource || pythonSource
  }

  val sinkFamilies = Seq(
    ("22", "path-traversal"),
    ("78", "command-injection"),
    ("79", "xss"),
    ("89", "sql-injection")
  )

  def matchesSink(cwe: String, name: String, fullName: String, rawCode: String): Boolean = {
    val identity = s"$name $fullName".toLowerCase
    val callName = name.toLowerCase
    val code = rawCode.trim.toLowerCase
    cwe match {
      case "22" =>
        Seq("fileinputstream", "fileoutputstream", "randomaccessfile", "java.nio.file.files.")
          .exists(identity.contains) ||
        Seq("new fileinputstream(", "new fileoutputstream(", "new randomaccessfile(",
            "new java.io.fileinputstream(", "new java.io.fileoutputstream(",
            "new java.io.randomaccessfile(").exists(code.startsWith) ||
        Seq("open", "send_file", "send_from_directory").contains(callName)
      case "78" =>
        callName == "exec" ||
        Seq("system", "popen", "run", "call", "check_output", "check_call").contains(callName) ||
        identity.contains("processbuilder") || code.startsWith("new processbuilder(") ||
        code.startsWith("new java.lang.processbuilder(")
      case "79" =>
        Seq("render_template_string", "markup", "make_response").contains(callName) ||
        identity.contains("java.io.printwriter") ||
        (Seq("write", "print", "println", "printf", "format").contains(callName) &&
          code.contains("response.getwriter()"))
      case "89" =>
        Seq("executequery", "executeupdate", "execute", "executemany").contains(callName)
      case _ => false
    }
  }

  val sources = sourceCalls.l
  val writer = Files.newBufferedWriter(Paths.get(outFile), StandardCharsets.UTF_8)
  try {
    writer.write("cwe\tfamily\tsink_file\tsink_line\tsink_code\tsource_file\tsource_line\tsource_code\tpath_length")
    writer.newLine()
    sinkFamilies.foreach { case (cwe, family) =>
      val sinks = cpg.call.filter { call =>
        // Raw code is used only for receiver/constructor identity. It is never searched
        // for a free-floating class name, which would classify log strings as sinks.
        matchesSink(cwe, call.name, call.methodFullName, call.code)
      }
      sinks.reachableByFlows(sources).foreach { flow =>
        val elements = flow.elements
        val source = elements.head
        val sink = elements.last
        writer.write(
          Seq(
            cwe,
            family,
            enc(sink.file.name.headOption.getOrElse("")),
            sink.lineNumber.map(_.toString).getOrElse(""),
            enc(sink.code),
            enc(source.file.name.headOption.getOrElse("")),
            source.lineNumber.map(_.toString).getOrElse(""),
            enc(source.code),
            elements.size.toString
          ).mkString("\t")
        )
        writer.newLine()
      }
    }
  } finally {
    writer.close()
  }
}
