对于 Signal Server，从 9.88.0 版本开始，项目结构发生了变化，主 JAR 文件名也已更新。您不应使用 TextSecureServer- .jar，而应使用 Signal-Server- .jar 作为主 JAR 文件。

我建议尝试这些代码：克隆信号服务器存储库：
```shell
git clone https://github.com/signalapp/Signal-Server.git
cd Signal-Server
```
使用 Maven 构建项目：
```shell
mvn clean install -DskipTests -Pexclude-abusive-message-filter
```
构建成功后，导航到服务目录：
``` shell
cd service
```
使用正确的主 JAR 文件运行信号服务器：
```shell
java -jar target/Signal-Server-9.89.0.jar server config/sample.yml

```
