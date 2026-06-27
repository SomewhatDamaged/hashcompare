from urllib.parse import urlsplit, parse_qs, urlparse
from workers import WorkerEntrypoint, Response, Request
import traceback
from json import dumps, loads


class Default(WorkerEntrypoint):
    json_header = {"content-type": "application/json;charset=UTF-8"}
    async def fetch(self, request: Request) -> Response:
        try:
            url = urlparse(request.url)
            pathname = url.path
            pathname = pathname[3:]
            if pathname.startswith("/hashcompare"):
                return await self.hashcompare(request)
            elif pathname.startswith("/hashlist"):
                return await self.hashlist(request)
            elif pathname.startswith("/scamscore"):
                return await self.scamscore(request)
            else:
                return Response(status=404)
        except Exception:
            headers = {"content-type": "text/plain;charset=UTF-8"}
            return Response(f"Traceback: {traceback.format_exc()}", headers=headers, status=500)

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
        dimensions: tuple[int,int] = (int(queries["dimensions"][0]), int(queries["dimensions"][1]))
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
        for datum in hashes_and_dimensions:
            hash_to_check: str = datum["phash"]
            dimensions_to_check: list[int] = datum["dimensions"]
            if hamming_distance(hash_from_user, hash_to_check) < 4:
                return 8
            if abs(
                settings.image_data["dimensions"]["width"]
                / settings.image_data["dimensions"]["height"]
                - image_data2["dimensions"]["width"]
                / image_data2["dimensions"]["height"]
            ) <= 0.05 and hamming_distance(hash_from_user, hash_to_check) < 10:
                return 5
        return 0

    async def hashes(self) -> list:
        return loads(str(await self.env.KV.get("phashes")).strip())

    async def hashes_and_dimensions(self) -> list[dict]:
        return loads(str(await self.env.KV.get("phashes_and_dimensions")).strip())


def hamming_distance(s1: str, s2: str) -> int:
    assert len(s1) == len(s2)
    return bin(int(s1, 16) ^ int(s2, 16)).count("1")