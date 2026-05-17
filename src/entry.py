from urllib.parse import urlsplit, parse_qs, urlparse
from workers import WorkerEntrypoint, Response, Request
import traceback
from json import dumps

hashes = [
    "9c4163ba63be945d06e24bb635dd364b59274d84b6589d14c924b64bb515e9b6",
    "d7a84ad6481da507b77277b04a5625ae1add5b71a569019763ce7ad4b5224a1d",
    "cf5d20d3982864b859af67c3887ca6539944f4bad9e555bb43e7281c8c54cb0f",
    "95d24a2d6a2c95924a294b2d34d610d15b6934f234f6596972d2b5f6e96dda9a",
    "c0fbf021d5dd8f509e1e8f92c206fdffa0a1e1e3c0ef28149bf6820e3fd81560",
    "95554aac68ab91b3cc8c9555f364b15748ed4d5c4ab9c4ca50a3e7309f3c6d4d",
    "810de21adee28dccaf3ba515da92eb30a5295af295540a8f250f5c8f5aea257d",
    "95554aa868abd3b3cc8c9715b364b1574ceccf184caad4c672a397344e7c2567",
    "95974a2d6a2cb596949b4b292f6634d619694b69349635f459695a9ab4d6a565",
    "97124ae96aecb5d64be94b6934d636934b69249634d65b695a9a34562d2d5a0b",
    "b796cb6d6f6db496cb894b6da49616924b69269634341b691692357429695ada",
    "888caaa57fb3d55b9403ea0562273be29998977a6265c884ec4e997b3fb062e6",
    "85fa69496aad62d7389bcb5a972699ad38e1cc2f3b90d2966f1a2499966d3e00",
    "c1feab8481868f30982fbe39c469f84b706977c1d586638f718c4ff4689e4a3c",
    "96cf38bf49e08343e3e5907c9246cd336c33b2dc65ec6dbb8adbcca69204c20d",
    "b7364a4b4be9b59497934b4b254424945b6b5b6b3494394d5a6a34b4a57d7869",
    "c1ffb94380c18f089c3dbe0cd6f0782e707877e250c361c778ff4f1e688f0c1c",
    "9c84cf69e37b9496cb09cb4ba4a536b65b4a25bd34b54b4a32b424a56b595a96",
    "97ab4af448580107b53eb5bb5ad5252a38855adf9e69943485226ad5b5ebb1b2",
    "bbac1388cc534c6133166616c8f9d0193e6c36e5d3072f9994f9ccf63f823336",
    "9405cbcf823aac35f5c6daba69dd74b45a4b7a5369f576ea6a4135140c8d320a",
    "c3e171e0fd039e13387e1e126a5e92e761e1278395ad45cd676c1e14ca5e3a5a",
    "95554aa868abdab3cc8c9715b16491774c4cdf394c8890a372b39734cc7d9377",
    "c715e351f87cdcaa78a238ae27972714275586514aab18ae9caeabd6a71cad14",
    "8c55e254e354f9c7d4aa763a53aa52aa95aa0e316ad32d552d558d552ed511c7",
    "90d26329663b94d24b253f9f3692594c2904b692d92de4d6a6f3496d56da27b9",
    "94659d646ac6688b659bb51e9754b22553a9589a6ddbad55953498aa9aab62c6",
    "b7964a694a68b4964a2b4b69349430b35b6b34b635f45b6b7496a565cb69d292",
    "c7e8810e9e077c3338336f9361506348dfec902f7ec395072193ffc1c0f87a74",
    "c3d4e3d4ef0f9c2b1c6b1c2b5c3bb1c463c5a35483f46a9c1c6b1c3a542b1f07",
    "c028d03acfff0fc72fc46060f038cfb98f1b9f9fb406f0c623e0cb030b171a7d",
    "ee0b41d411f202ff3e0076435d342bbb9474ec8ffaebe3188555ae8616c74d34",
    "80bd9e0b7f4361dc6b509eac9e873cc3c0fd6f026f0fc07c6bd294871f009b70",
    "af565cab5011a80cbe6c777552a9295e52ba17f7acd3030b739c77a8ab445429",
    "94c6c72da33d94d78168296836b43a432968369439687bf876b3650c73bde2f3",
    "94659d646ac6689b659bb51e9654b22553a9599a6ddbad55853498aa9aab62ca",
    "c8b6914a36edc89a9134e6ec39dba6655c98e23331eee6111d7aa9f51487c31c",
    "af56d4ab5810a808be54ff6552a8295c5aba5cf79c53094b529a77aea35564a9",
    "9619f9e4c957c58ecf74b4a99639c956f466b2896f4317224946393794a94678",
    "ce1c23a3f07b9de0718e59ea2101673e0bf0bc7d07a3f80e95cbd80ea7b0b0dc",
    "c0009b0136eae4953db36626c2cccb553f2b2ccc3f3748b760fa35d93b23cecc",
    "95554aa868abd2b3c4cc9355b144d9774cc84ab9648ab2a767309f7c694f7363",
    "9513ea886ae895509117e8cc66c83936193266cf6ecd19b2366e6edd6b993d13",
    "c0ffb542c54187e9d515bf168e129e02e83f38309eff23e0b0e783bb10e023ef",
    "8ce5eee5f18cf19a733b731a476b0e670ee70ccc9c795baa1512319a4c6222c6",
    "a00c5e374fe32dbd25515a826271ad6dd2f6a101e4a9b83856f2ad155fa34e67",
    "81b780277ec87fd83a09942791b66fb2c85b835d7ec918f681963da2c1a96f49",
    "c0ab85abcdc1c355fa147ad67ae4386c746c1549c44b4c9a4cbb4ef261973f25",
    "c55a795cbd428f83d0bc1aa55abd16adc0fc68713742a55aa55a21529fc3c8f9",
    "95554aa868abd2b3c4cc9355b144d9774cc84ab9648ab2b367309f7c694f7b43",
    "c3f5e2dfe387df011c381c235c3a947268e0a3c5a1fc629ea35c9c1e543e5723",
    "95d94e2c6e2695d14aad69a734d31be9492db6d2c90dcb2da6d2ad254aa916d2",
    "d7f46f3b080704813fb83bde696b3694196acb3ca2956141fb70df2a949c4b23",
    "8179d6b29e858d88ab72a529d2adab77e14b58e791a52a29af5a54bc6ed42542",
    "817f7c937ec09324913fe4db6cd01b25936564d4c0bf5b23b700b64c6c9bc1b9",
    "be5545bf518e0bc027c3a81c542a6a3e2b5757e300bfb91cb8dc567355a2aa53",
    "fe5541bb53840bc0a5c3ac5d54af6e172b7716ab389c981c2b5952a745abb255",
    "9e6ce083e197976c6aaa6c93324d336c4cb272ef534d4c92da60d74dd493c92a",
    "815d5e322f8100fc315f5aea6375dd65db92a50dacf1989a070f8d1d5ae23a78"
]

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
        # result: bool = compare_hashes(hash_from_user)
        result: bool = await self.find_hash(hash_from_user)
        return Response(f'{{"result": {str(result).lower()}}}', headers=self.json_header, status=404 if result else 200)

    async def hashlist(self, request: Request) -> Response:
        return Response(dumps(hashes), headers=self.json_header)

    async def find_hash(self, phash: str) -> bool:
        query = "SELECT * FROM hashes WHERE HAMMING(hash,?)"
        results = await self.env.DB.prepare(query).bind(phash).all()
        if results.results[0]:
            return True
        return False

def compare_hashes(hash_from_user: str) -> bool:
    if hash_from_user in hashes:
        return True
    for hash_to_check in hashes:
        if hamming_distance(hash_from_user, hash_to_check) < 4:
            return True
    return False

def hamming_distance(s1: str, s2: str) -> int:
    assert len(s1) == len(s2)
    return bin(int(s1, 16) ^ int(s2, 16)).count("1")

def hamming(s1, s2):
    s1 = str(s1)
    s2 = str(s2)
    if len(s1) != len(s2):
        return False
    return hamming_distance(s1, s2) < 4