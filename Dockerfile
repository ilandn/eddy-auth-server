FROM tomcat:10.1.18-jdk17

ADD target/eddy-auth-server.war /usr/local/tomcat/webapps/
COPY target/classes/server.xml /usr/local/tomcat/conf/server.xml

#ENV JPDA_ADDRESS="*:5005"
#ENV JPDA_TRANSPORT="dt_socket"

#EXPOSE 5005 5005
EXPOSE 8080
EXPOSE 8443

ENV CATALINA_OPTS="-Djavax.net.ssl.trustStore=/usr/local/tomcat/conf/ssl/cacerts -Djavax.net.ssl.trustStorePassword=changeit"
#CMD chmod +x /usr/local/tomcat/bin/catalina.sh
CMD ["catalina.sh", "run"]
#CMD ["catalina.sh", "jpda" ,"run"]