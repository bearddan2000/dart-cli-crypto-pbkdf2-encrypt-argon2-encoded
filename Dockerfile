FROM google/dart

WORKDIR /app

ADD ./bin/pubspec.* /app/
RUN pub get
ADD ./bin /app
RUN pub get --offline

CMD []
ENTRYPOINT ["/usr/bin/dart", "main.dart"]
