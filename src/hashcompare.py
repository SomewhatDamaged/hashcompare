from urllib.parse import urlsplit, parse_qs, urlparse
from workers import WorkerEntrypoint, Response, Request, fetch
import traceback
from json import dumps, loads


class Default(WorkerEntrypoint):
    json_header = {"content-type": "application/json;charset=UTF-8"}
    async def fetch(self, request: Request) -> Response:
        try:
            url = urlparse(request.url)
            pathname = url.path
            pathname = pathname[3:]
            if request.method == "GET":
                if pathname.startswith("/hashcompare"):
                    return await self.hashcompare(request)
                elif pathname.startswith("/hashlist"):
                    return await self.hashlist(request)
                elif pathname.startswith("/scamscore"):
                    return await self.scamscore(request)
            if request.method == "POST":
                if pathname.startswith("/report"):
                    return await self.report(request)
            return Response(status=404)
        except Exception:
            headers = {"content-type": "text/plain;charset=UTF-8"}
            return Response(f"Traceback: {traceback.format_exc()}", headers=headers, status=500)

    # POST Handlers

    async def report(self, request: Request) -> Response:
        headers = dict(request.headers)
        # Check auth presence and if it has a bearer token
        if "authorization" not in headers.keys():
            return Response('{"error": "Missing \'authorization\' parameter"}', headers=self.json_header, status=400)
        if not headers["authorization"].startswith("Bearer "):
            return Response('{"error": "Bad \'authorization\' parameter"}', headers=self.json_header, status=400)
        # Check url presence
        if "url" not in headers.keys():
            return Response('{"error": "Missing \'url\' parameter"}', headers=self.json_header, status=400)
        # Check authorization
        key = headers["authorization"].split(" ")[1]
        authorized_data = loads(str(await self.env.KEYS.get(key)).strip())
        if authorized_data is None:
            return Response('{"error": "Invalid \'key\' parameter"}', headers=self.json_header, status=401)
        if "report" not in authorized_data["access"]:
            return Response('{"error": "You do not have access to this endpoint"}', headers=self.json_header, status=403)
        # Checking url is valid
        url = headers["url"]
        # Downloading and checking it
        file_response = await fetch(url)
        if not file_response.ok:
            return Response(f'{{"error": "Could not download file from: {url}\nError status (from remote server): {file_response.status}"}}', headers=self.json_header, status=400)
        if not file_response.headers["content-type"].startswith("image/"):
            return Response(f'{{"error": "File is not type \'image/\': {file_response.headers["content-type"]}"}}', headers=self.json_header, status=400)
        # Build file name + extension
        file_name = url.rsplit("/",1)[1].replace(".", "_")
        extension = file_response.headers["content-type"].split("/")[1]
        # Upload to R2!
        await self.env.REPORTSTORAGE.put(f"api-reported/{key}/{file_name}.{extension}", file_response.body, block=True)
        return Response('{"result": "success"}', headers=self.json_header, status=200)

    # GET Handlers

    async def hashcompare(self, request: Request) -> Response:
        url = urlsplit(request.url)
        queries = parse_qs(url.query)
        if "hash" not in queries.keys():
            return Response('{"error": "Missing \'hash\' parameter"}', headers=self.json_header, status=400)
        hash_from_user = queries["hash"][0]
        if len(hash_from_user) != 64:
            return Response('{"error": "\'hash\' parameter must be 64 characters long"}', headers=self.json_header, status=400)
        result: bool = await self.compare_hashes(hash_from_user)
        return Response(f'{{"result": {str(result).lower()}}}', headers=self.json_header, status=404 if not result else 200)

    async def hashlist(self, request: Request) -> Response:
        return Response(dumps(await self.hashes()), headers=self.json_header)

    async def scamscore(self, request: Request) -> Response:
        url = urlsplit(request.url)
        queries = parse_qs(url.query)
        errors: list = []
        if "hash" not in queries.keys():
            errors.append('Missing \'hash\' parameter')
        if "dimensions" not in queries.keys():
            errors.append('Missing \'dimensions\' parameter')
        if errors:
            return Response(f'{{"error": {errors}}}', headers=self.json_header, status=400)
        dimensions: tuple[int,int] = (int(queries["dimensions"][0].split(',',1)[0]), int(queries["dimensions"][0].split(',',1)[1]))
        hash_from_user = queries["hash"][0]
        result: int = await self.compare_hashes_and_dimensions(hash_from_user, dimensions)
        return Response(f'{{"result": {int(result)}}}', headers=self.json_header, status=404 if not result else 200)

    async def compare_hashes(self, hash_from_user: str) -> bool:
        hashes = await self.hashes()
        if hash_from_user in hashes:
            return True
        for hash_to_check in hashes:
            if hamming_distance(hash_from_user, hash_to_check) < 4:
                return True
        return False

    async def compare_hashes_and_dimensions(self, hash_from_user: str, dimensions: tuple[int, int]) -> int:
        hashes = await self.hashes()
        if hash_from_user in hashes:
            return 10
        hashes_and_dimensions = await self.hashes_and_dimensions()
        best_score: Union[float, int] = 0
        for datum in hashes_and_dimensions:
            hash_to_check: str = datum["phash"]
            dimensions_to_check: list[int] = datum["dimensions"]
            if hamming_distance(hash_from_user, hash_to_check) < 4:
                return 8
            hit = 1 - abs(dimensions[0] / dimensions[1] - dimensions_to_check[0] / dimensions_to_check[1])
            ham = max(10 - hamming_distance(hash_from_user, hash_to_check), 0)
            score = hit * ham
            if score > best_score:
                best_score = score
        return int(round(best_score))

    async def hashes(self) -> list:
        return loads(str(await self.env.KV.get("phashes")).strip())

    async def hashes_and_dimensions(self) -> list[dict]:
        return loads(str(await self.env.KV.get("phashes_and_dimensions")).strip())


def hamming_distance(s1: str, s2: str) -> int:
    assert len(s1) == len(s2)
    return bin(int(s1, 16) ^ int(s2, 16)).count("1")