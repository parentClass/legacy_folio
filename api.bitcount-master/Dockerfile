FROM python:3.7
COPY . /app
WORKDIR /app
RUN pip install --upgrade pip && \
    pip install build-essential automake pkg-config libtool libffi-dev libgmp-dev && \
    pip install secp256k1 && \
    pip install -r requirements.txt
EXPOSE 5000
CMD python ./run_app.py

