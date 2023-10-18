FROM python:3.12-alpine
WORKDIR /code
RUN mkdir /root/Downloads
RUN apk --no-cache add swig git gcc pcsc-lite-dev musl-dev bash curl git g++ make libffi-dev openssl-dev py-openssl

RUN git clone https://github.com/taers232c/GAMADV-XTD3.git /opt/gam \
    &&  ln -s /opt/gam/src/gam.py /usr/bin/gam \
    && touch /opt/gam/src/nobrowser.txt \
    && touch /opt/gam/src/noupdatecheck.txt
RUN pip install --no-cache-dir --upgrade -r /opt/gam/src/requirements.txt

COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt

COPY ./app /code/app


CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]
