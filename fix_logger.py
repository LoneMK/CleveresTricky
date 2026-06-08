file_path = "service/src/main/java/cleveres/tricky/cleverestech/WebServer.kt"
with open(file_path, "r") as f:
    content = f.read()

content = content.replace("Logger.w(", "Logger.e(")

with open(file_path, "w") as f:
    f.write(content)
