from re import search
from gzip import decompress

# Obs: é preciso utilizar o "Match and Replace" do Burp e trocar para "Accept-Encoding: gzip"

def response(flow):
	headers = flow.response.headers
	path = flow.request.path

	header_sign = "Content-Type"

	if header_sign in headers:
		match = search(r'(text|application)/(x-|)javascript', headers[header_sign])

		if match is not None:
				# pega apenas o nome do arquivo JavaScript
				match = search(r'(?<=/)(\w|[_-])+.js($|(?=\?))', path)

				if match is not None:

					with open(match.group(0), "w") as f:

						# caso for um JS puro
						if not "Content-Encoding" in headers:
							print(flow.response.data.content.decode("utf-8"), file=f)
							return

						# arquivo comprimido em GZIP
						descompressed_js = decompress(flow.response.data.content)
						print(descompressed_js.decode("utf-8"), file=f)
