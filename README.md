# DHIS authentication provider for Openfire
The following instructions describe how to use DHIS authentication in Openfire.

1. Build this project using Maven
  * ***dhis.provider-1.0.0-SNAPSHOT.jar*** should be created in ***target*** directory
2. Set up Openfire server
  * download the latest [Openfire server](http://www.igniterealtime.org/downloads/) for your platform
  * run the installer or unzip the archive
  * copy ***dhis.provider-1.0.0-SNAPSHOT.jar*** generated before to ***openfire/lib*** directory
  * copy ***base64-2.3.8.jar*** to ***openfire/lib*** directory (from *~/.m2/repository/net/iharder/base64/2.3.8/*)
3. Run and configure Openfire server
  * run Openfire from ***openfire/bin*** directory (***./openfire start*** for Linux systems)
  * go to [Openfire Admin Console](http://localhost:9090/) and go throught the basic setup if you want
  * go to ***System Properties*** and change ***provider.auth.className*** to ***org.hisp.dhis.provider.DHISAuthProvider***
  * if your DHIS server runs on the address different from [http://localhost:8082](http://localhost:8082) set ***dhis.server.url*** property to your server address (including port number)
  * restart the server (***./openfire restart*** for Linux systems)

Note that you should start your local DHIS server before running Openfire with this configuration. You should also make sure that your firewall does not block port ***5222***.
