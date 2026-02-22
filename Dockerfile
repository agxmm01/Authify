FROM amazoncorretto:25.0.2 AS build

WORKDIR /app

# Install required tools for Maven wrapper
RUN yum install -y tar gzip && yum clean all

COPY .mvn .mvn
COPY src src
COPY pom.xml .
COPY mvnw .

RUN chmod +x mvnw
RUN ./mvnw clean install -DskipTests


FROM amazoncorretto:25.0.2

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]