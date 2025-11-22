from re import search
from gzip import decompress as gzip_decompress
from brotli import decompress as br_decompress

# Obs: é preciso utilizar o "Match and Replace" do Burp e trocar para "Accept-Encoding: gzip"


def response(flow):
    headers = flow.response.headers
    path = flow.request.path

    header_sign = "Content-Type"

    if header_sign in headers:
        match = search(r"(text|application)/(x-|)javascript", headers[header_sign])

        if match is not None:
            # pega apenas o nome do arquivo JavaScript
            match = search(r"(?<=/)(\w|[_-])+.js($|(?=\?))", path)

            if match is not None:

                with open(match.group(0), "w") as f:

                    # caso for um JS puro
                    if not "Content-Encoding" in headers:
                        print(flow.response.data.content.decode("utf-8"), file=f)
                        return

                    content_encoding = headers["Content-Encoding"]

                    # caso haja compressão no arquivo, seja ele gzip ou br...
                    # descomprime e joga pro arquivo local

                    if content_encoding == "gzip":
                        # arquivo comprimido em GZIP
                        decompressed_js = gzip_decompress(flow.response.data.content)

                    elif content_encoding == "br":
                        # arquivo comprimido em Brotli
                        decompressed_js = br_decompress(flow.response.data.content)

                    print(decompressed_js.decode("utf-8"), file=f)
