from urllib.parse import urlsplit, parse_qs, urlparse
from workers import WorkerEntrypoint, Response, Request
import traceback
from json import dumps, load


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
            else:
                return Response(status=404)
        except Exception:
            headers = {"content-type": "text/plain;charset=UTF-8"}
            return Response(traceback.format_exc(), headers=headers, status=500)

    async def hashcompare(self, request: Request) -> Response:
        url = urlsplit(request.url)
        queries = parse_qs(url.query)
        if "hash" not in queries.keys():
            return Response('{"error": "Missing \'hash\' parameter"}', headers=self.json_header, status=400)
        hash_from_user = queries["hash"][0]
        if len(hash_from_user) != 64:
            return Response('{"error": "\'hash\' parameter must be 64 characters long"}', headers=self.json_header, status=400)
        result: bool = await self.compare_hashes(hash_from_user)
        return Response(f'{{"result": {str(result).lower()}}}', headers=self.json_header, status=404 if result else 200)

    async def hashlist(self, request: Request) -> Response:
        return Response(dumps(await self.hashes()), headers=self.json_header)

    async def compare_hashes(self, hash_from_user: str) -> bool:
        if hash_from_user in await self.hashes():
            return True
        for hash_to_check in await self.hashes():
            if hamming_distance(hash_from_user, hash_to_check) < 4:
                return True
        return False

    async def hashes(self) -> list:
        return ( await self.env.KV.get("scam_hashes") )["phashes"]


def hamming_distance(s1: str, s2: str) -> int:
    assert len(s1) == len(s2)
    return bin(int(s1, 16) ^ int(s2, 16)).count("1")