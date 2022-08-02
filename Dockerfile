FROM adoptopenjdk/openjdk11:ubi
ADD target/gateway-1.0.jar gateway.jar
ENTRYPOINT ["java","-jar","gateway.jar"]