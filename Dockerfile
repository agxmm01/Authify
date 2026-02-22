FROM openjdk@sha256:9c484cfbe3cda24c78838da9ad333be25c1d3bcf4c9788b4f5cf34911c07c1cf AS build

WORKDIR /app

COPY .mvn .mvn
COPY src src
COPY pom.xml .
COPY mvnw .

RUN chmod +x mvnw
RUN ./mvnw install -DskipTests

FROM openjdk@sha256:9c484cfbe3cda24c78838da9ad333be25c1d3bcf4c9788b4f5cf34911c07c1cf

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["java", "-jar", "app.jar"]