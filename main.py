# -*- coding: utf-8 -*-
import hashlib
import json
import time
import requests
import json
import random
from Crypto.Cipher import DES
import base64
from wasmtime import Store, Module, Instance

lookup = ["Z", "m", "s", "e", "r", "b", "B", "o", "H", "Q", "t", "N", "P", "+", "w", "O", "c", "z", "a", "/", "L", "p", "n", "g", "G", "8", "y", "J", "q", "4", "2", "K", "W", "Y", "j", "0", "D", "S", "f", "d", "i", "k", "x", "3", "V", "T", "1", "6", "I", "l", "U", "A", "F", "M", "9", "7", "h", "E", "C", "v", "u", "R", "X", "5",]
crc_table = [0, 1996959894, 3993919788, 2567524794, 124634137, 1886057615, 3915621685, 2657392035, 249268274, 2044508324, 3772115230, 2547177864, 162941995, 2125561021, 3887607047, 2428444049, 498536548, 1789927666, 4089016648, 2227061214, 450548861, 1843258603, 4107580753, 2211677639, 325883990, 1684777152, 4251122042, 2321926636, 335633487, 1661365465, 4195302755, 2366115317, 997073096, 1281953886, 3579855332, 2724688242, 1006888145, 1258607687, 3524101629, 2768942443, 901097722, 1119000684, 3686517206, 2898065728, 853044451, 1172266101, 3705015759, 2882616665, 651767980, 1373503546, 3369554304, 3218104598, 565507253, 1454621731, 3485111705, 3099436303, 671266974, 1594198024, 3322730930, 2970347812, 795835527, 1483230225, 3244367275, 3060149565, 1994146192, 31158534, 2563907772, 4023717930, 1907459465, 112637215, 2680153253, 3904427059, 2013776290, 251722036, 2517215374, 3775830040, 2137656763, 141376813, 2439277719, 3865271297, 1802195444, 476864866, 2238001368, 4066508878, 1812370925, 453092731, 2181625025, 4111451223, 1706088902, 314042704, 2344532202, 4240017532, 1658658271, 366619977, 2362670323, 4224994405, 1303535960, 984961486, 2747007092, 3569037538, 1256170817, 1037604311, 2765210733, 3554079995, 1131014506, 879679996, 2909243462, 3663771856, 1141124467, 855842277, 2852801631, 3708648649, 1342533948, 654459306, 3188396048, 3373015174, 1466479909, 544179635, 3110523913, 3462522015, 1591671054, 702138776, 2966460450, 3352799412, 1504918807, 783551873, 3082640443, 3233442989, 3988292384, 2596254646, 62317068, 1957810842, 3939845945, 2647816111, 81470997, 1943803523, 3814918930, 2489596804, 225274430, 2053790376, 3826175755, 2466906013, 167816743, 2097651377, 4027552580, 2265490386, 503444072, 1762050814, 4150417245, 2154129355, 426522225, 1852507879, 4275313526, 2312317920, 282753626, 1742555852, 4189708143, 2394877945, 397917763, 1622183637, 3604390888, 2714866558, 953729732, 1340076626, 3518719985, 2797360999, 1068828381, 1219638859, 3624741850, 2936675148, 906185462, 1090812512, 3747672003, 2825379669, 829329135, 1181335161, 3412177804, 3160834842, 628085408, 1382605366, 3423369109, 3138078467, 570562233, 1426400815, 3317316542, 2998733608, 733239954, 1555261956, 3268935591, 3050360625, 752459403, 1541320221, 2607071920, 3965973030, 1969922972, 40735498, 2617837225, 3943577151, 1913087877, 83908371, 2512341634, 3803740692, 2075208622, 213261112, 2463272603, 3855990285, 2094854071, 198958881, 2262029012, 4057260610, 1759359992, 534414190, 2176718541, 4139329115, 1873836001, 414664567, 2282248934, 4279200368, 1711684554, 285281116, 2405801727, 4167216745, 1634467795, 376229701, 2685067896, 3608007406, 1308918612, 956543938, 2808555105, 3495958263, 1231636301, 1047427035, 2932959818, 3654703836, 1088359270, 936918000, 2847714899, 3736837829, 1202900863, 817233897, 3183342108, 3401237130, 1404277552, 615818150, 3134207493, 3453421203, 1423857449, 601450431, 3009837614, 3294710456, 1567103746, 711928724, 3020668471, 3272380065, 1510334235, 755167117]


class newDES:
    def __init__(self, key):
        self.length = DES.block_size
        self.des = DES.new(key.encode("utf8"), DES.MODE_ECB)
        self.unpad = lambda date: date[0:-ord(date[-1])]

    def pad(self, text):
        count = len(text.encode('utf8'))
        add = self.length - (count % self.length)
        entext = text + (chr(add) * add)
        return entext

    def encrypt(self, encrData):
        res = self.des.encrypt(self.pad(encrData).encode("utf8"))
        msg = base64.b64encode(res).decode("utf8")
        return msg

    def decrypt(self, decrData):
        res = base64.decodebytes(decrData.encode("utf8"))
        msg = self.des.decrypt(res).decode("utf8")
        return self.unpad(msg)


def randhex(length):
    characters = "abcdef1234567890"
    random_string = ''.join(random.choices(characters, k=length))
    return random_string


def md5(str: str):
    return hashlib.md5(str.encode()).hexdigest()


def random_str():
    data = ""
    for i in range(4):
        data += (format((int((1 + random.random()) * 65536) | 0), "x")[1:])
    return data


def custom_b64encode(data_to_encode: bytes, custom_alphabet: str) -> str:
    STANDARD_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    if len(custom_alphabet) != 64:
        raise ValueError("自定义码表必须包含 64 个字符！")
    standard_encoded_str = base64.b64encode(data_to_encode).decode('ascii')
    translator = str.maketrans(STANDARD_ALPHABET, custom_alphabet)
    return standard_encoded_str.translate(translator)


def crc32(data):
    crc = 0xFFFFFFFF
    if isinstance(data, str):
        data = data.encode()
        for byte in data:
            crc = (crc >> 8) ^ crc_table[(crc & 0xFF) ^ byte]
        return -1 ^ crc ^ 3988292384
    for byte in data:
        crc = (crc >> 8) ^ crc_table[crc ^ byte]
    return -1 ^ crc ^ 3988292384


def mnsv2(xhs_key, api_url):
    start_time = int(time.time() * 1000)
    xhs_api = "xhs-pc-web"
    array = [119, 104, 96, 41]

    random_int = int(random.random() * 4294967295)
    xor_num = random_int & 255

    temp_array = [(random_int >> (i * 8)) & 0xFF for i in range(4)]
    array += temp_array

    ctime = int(time.time() * 1000)
    temp_array = [(ctime >> (i * 8)) & 0xff for i in range(8)]
    temp_val = sum(temp_array[1:]) & 0xFF
    temp_array = [(temp_val ^ 41)] + [val ^ 41 for val in temp_array[1:]]
    array += temp_array

    temp_array = [(start_time >> (i * 8)) & 0xFF for i in range(8)]
    array += temp_array

    access_time = 15  # 访问次数 每次+1
    temp_array = [(access_time >> (i * 8)) & 0xFF for i in range(4)]
    array += temp_array

    window_property = 1292  # Object.getOwnPropertyNames(window) 返回的Array长度
    temp_array = [(window_property >> (i * 8)) & 0xFF for i in range(4)]
    array += temp_array

    temp_array = [(len(api_url) >> (i * 8)) & 0xFF for i in range(4)]
    array += temp_array

    api_url_encode = hashlib.md5(api_url.encode()).hexdigest()  # url的md5加密值
    decimal_list = [int(api_url_encode[i:i+2], 16) for i in range(0, len(api_url_encode), 2)]
    temp_array = [decimal ^ xor_num for decimal in decimal_list]
    array += temp_array[0:8]

    temp_array = [len(xhs_key)] + list(xhs_key.encode('utf-8'))
    array += temp_array
    temp_array = [len(xhs_api)] + list(xhs_api.encode('utf-8'))
    array += temp_array

    xhs_array = [115, 248, 83, 102, 103, 201, 181, 131, 99, 94, 4, 68, 250, 132, 21]  # 常量Array
    window_ee019d93900dcee2bdafbe5894e6c8a9 = 1  # window._ee019d93900dcee2bdafbe5894e6c8a9的值
    window_dssts = 0  # window.dssts的值
    temp_array = [
        1,
        xor_num ^ xhs_array[0],
        window_ee019d93900dcee2bdafbe5894e6c8a9 ^ xhs_array[1],
        window_dssts ^ xhs_array[2],
        1 ^ xhs_array[3],  # 100
        0 ^ xhs_array[4],  # 101
        0 ^ xhs_array[5],  # 102
        0 ^ xhs_array[6],  # 103
        2 ^ xhs_array[7],  # 104
        0 ^ xhs_array[8],  # 106
        0 ^ xhs_array[9],  # 107
        3 ^ xhs_array[10],  # 401
        0 ^ xhs_array[11],
        0 ^ xhs_array[12],  # 109
        0 ^ xhs_array[13],
        0 ^ xhs_array[14],
    ]
    array += temp_array
    byte_data = bytes(array)

    # wasm 载入初始化
    store = Store()
    module = Module.from_file(store.engine, './000238fa')
    instance = Instance(store, module, [])
    exports = instance.exports(store)
    malloc = exports['malloc']
    free = exports['free']
    modify_array = exports['xy_18d12b8e541b1fd80b1c3c2eeb63a208']
    encrypt_array = exports['xy_daa92688ff9309e1a29d25224fd0164a']
    memory = exports['memory']

    # 数组偏移
    ptr = malloc(store, len(byte_data))
    memory.write(store, byte_data, ptr)
    # print('原始数组: ', list(memory.read(store, ptr, ptr + len(byte_data))))
    array_result = modify_array(store, ptr, len(byte_data), 858975407)
    modified_byte = memory.read(store, array_result, array_result + len(byte_data))

    free(store, array_result)
    free(store, ptr)

    # 数组加密
    ptr = malloc(store, len(modified_byte))
    memory.write(store, modified_byte, ptr)
    # print('偏移数组: ', list(memory.read(store, ptr, ptr + len(byte_data))))
    encode_result = encrypt_array(store, ptr, len(modified_byte))
    encode_memory = memory.read(store)
    encode_str = []
    for idx in range(encode_result, len(encode_memory)):
        byte = encode_memory[idx]
        if byte == 0:
            break
        encode_str.append(chr(byte))
    encode_str = 'mns0101_' + ''.join(encode_str)
    return encode_str


# x8是localstorage中的b1值
x8 = "I38rHdgsjopgIvesdVwgIC+oIELmBZ5e3VwXLgFTIxS3bqwErFeexd0ekncAzMFYnqthIhJeD9MDKutRI3KsYorWHPtGrbV0P9WfIi/eWc6eYqtyQApPI37ekmR6QL+5Ii6sdneeSfqYHqwl2qt5B0DBIx++GDi/sVtkIxdsxuwr4qtiIhuaIE3e3LV0I3VTIC7e0utl2ADmsLveDSKsSPw5IEvsiVtJOqw8BuwfPpdeTFWOIx4TIiu6ZPwrPut5IvlaLbgs3qtxIxes1VwHIkumIkIyejgsY/WTge7eSqte/D7sDcpipedeYrDtIC6eDVw2IENsSqtlnlSuNjVtIvoekqt3cZ7sVo4gIESyIhE2+9DUIvzy4I8OIic7ZPwAIviR4o/sDLds6PwVIC7eSd7e0/E4IEve1ccMtVwUIids3s/sxZNeiVtbcUeeYVwvIv4az/7eSuw5LnAsfqwrIxltIxZSouwOgVwpsr4heU/e6LveDPwFIvgs1ros1DZiIi7sjbos3grFIE0e3PtvIibROqwOOqthIxesxPw7IhAeVPthIh/sYqtSGqwymPwDIvIkI3It4aGS4Y/eiutjIimrIEOsSVtzBoFM/9vej9ZvIiENGutzrutlIvve3PtUOpKe1lds3LMyIh7s3BOs1qtsBVwNIvgefVwIIkge60VLICdeYsveSqtMI37sVuwu4B8qIkWgIvgsxFOekcOe0WosDutrIkD5IvcaZPw4IC4AIE/e6D4F"
# a1是cookie中的a1
a1 = "19960bf8ec1rjve1ytf5z5tlyot8qivtchg7ucv8k50000165098"

x3 = mnsv2(a1, '/api/sns/web/v1/feed{"source_note_id":"68ac32fa000000001d0294e0","image_formats":["jpg","webp","avif"],"extra":{"need_body_topic":"1"},"xsec_source":"pc_feed","xsec_token":"AB-zwgDU89Zb3TEgrHeqzRupLvsYC5-ul71eJFJwf08vI="}')
print("x3 =====>", x3)

mmm = {"s0": 5, "s1": "", "x0": "1", "x1": "4.2.6", "x2": "Windows", "x3": "xhs-pc-web", "x4": "4.80.0", "x5": a1, "x6": "", "x7": "", "x8": x8, "x9": crc32(x8), "x10": 3, "x11": "normal"}
x_s_common = custom_b64encode(json.dumps(mmm, separators=(',', ':')).encode(), 'ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5')
print("x_s_common =====>", x_s_common)

nnn = {"x0": "4.2.6", "x1": "xhs-pc-web", "x2": "Windows", "x3": x3, "x4": "object"}
x_s = "XYS_"+custom_b64encode(json.dumps(nnn, separators=(',', ':')).encode(), 'ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5')
print("x_s =====>", x_s)

x_t = str(int(time.time() * 1000))
print("x_t =====>", x_t)

x_b3_traceId = random_str()
x_xray_traceid = md5(x_b3_traceId)
print("x_b3_traceId =====>", x_b3_traceId)
print("x_xray_traceid =====>", x_xray_traceid)


headers = {
    "accept": "application/json, text/plain, */*",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
    "cache-control": "no-cache",
    "content-type": "application/json;charset=UTF-8",
    "origin": "https://www.xiaohongshu.com",
    "pragma": "no-cache",
    "priority": "u=1, i",
    "referer": "https://www.xiaohongshu.com/",
    "sec-ch-ua": "\"Chromium\";v=\"140\", \"Not=A?Brand\";v=\"24\", \"Google Chrome\";v=\"140\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "x-b3-traceid": x_b3_traceId,
    "x-s": x_s,
    "x-s-common": x_s_common,
    "x-t": x_t,
    "x-xray-traceid": x_xray_traceid
}
cookies = {
    "abRequestId": "3449f360-6569-5a65-a309-9e1e28662c5e",
    "webBuild": "4.81.0",
    "xsecappid": "xhs-pc-web",
    "a1": "19960bf8ec1rjve1ytf5z5tlyot8qivtchg7ucv8k50000165098",
    "webId": "1fd898ad81e2171639c2a1275f474fe8",
    "acw_tc": "0a0bb01117582647916004442e8e6016655037a5fde5fe626c31f131d953ca",
    "websectiga": "a9bdcaed0af874f3a1431e94fbea410e8f738542fbb02df1e8e30c29ef3d91ac",
    "sec_poison_id": "216b254c-8f11-4bd1-8751-49159115491f",
    "web_session": "030037afffa9a30c0e8b9bbbb42f4ac62e426b",
    "loadts": "1758264792144",
    "unread": "{%22ub%22:%2268bc1677000000001d01cd2f%22%2C%22ue%22:%2268c38cac000000001c03cc4f%22%2C%22uc%22:27}",
    "gid": "yjjK8Di08jSfyjjK8DiYdxShSyFVhdyv9i2ukYT291vl9W28YA3h97888yK28jY8WdjW8SWW"
}
url = "https://edith.xiaohongshu.com/api/sns/web/v1/feed"
data = {
    "source_note_id": "68ac32fa000000001d0294e0",
    "image_formats": [
        "jpg",
        "webp",
        "avif"
    ],
    "extra": {
        "need_body_topic": "1"
    },
    "xsec_source": "pc_feed",
    "xsec_token": "AB-zwgDU89Zb3TEgrHeqzRupLvsYC5-ul71eJFJwf08vI="
}
data = json.dumps(data, separators=(',', ':'))
response = requests.post(url, headers=headers, cookies=cookies, data=data)

print(response.text)


# =============================
# 以下是get请求测试代码
# =============================

x3 = mnsv2(a1, '/api/sns/web/v1/search/querytrending?source=UserPage&search_type=trend&last_query=&last_query_time=0&word_request_situation=FIRST_ENTER&hint_word=&hint_word_type=&hint_word_request_id=')
print("x3 =====>", x3)

mmm = {"s0": 5, "s1": "", "x0": "1", "x1": "4.2.6", "x2": "Windows", "x3": "xhs-pc-web", "x4": "4.80.0", "x5": a1, "x6": "", "x7": "", "x8": x8, "x9": crc32(x8), "x10": 3, "x11": "normal"}
x_s_common = custom_b64encode(json.dumps(mmm, separators=(',', ':')).encode(), 'ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5')
print("x_s_common =====>", x_s_common)

nnn = {"x0": "4.2.6", "x1": "xhs-pc-web", "x2": "Windows", "x3": x3, "x4": "object"}
x_s = "XYS_"+custom_b64encode(json.dumps(nnn, separators=(',', ':')).encode(), 'ZmserbBoHQtNP+wOcza/LpngG8yJq42KWYj0DSfdikx3VT16IlUAFM97hECvuRX5')
print("x_s =====>", x_s)

x_t = str(int(time.time() * 1000))
print("x_t =====>", x_t)

x_b3_traceId = random_str()
x_xray_traceid = md5(x_b3_traceId)
print("x_b3_traceId =====>", x_b3_traceId)
print("x_xray_traceid =====>", x_xray_traceid)


headers = {
    "accept": "application/json, text/plain, */*",
    "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
    "cache-control": "no-cache",
    "content-type": "application/json;charset=UTF-8",
    "origin": "https://www.xiaohongshu.com",
    "pragma": "no-cache",
    "priority": "u=1, i",
    "referer": "https://www.xiaohongshu.com/",
    "sec-ch-ua": "\"Chromium\";v=\"140\", \"Not=A?Brand\";v=\"24\", \"Google Chrome\";v=\"140\"",
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": "\"Windows\"",
    "sec-fetch-dest": "empty",
    "sec-fetch-mode": "cors",
    "sec-fetch-site": "same-site",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "x-b3-traceid": x_b3_traceId,
    "x-s": x_s,
    "x-s-common": x_s_common,
    "x-t": x_t,
    "x-xray-traceid": x_xray_traceid
}
cookies = {
    "abRequestId": "3449f360-6569-5a65-a309-9e1e28662c5e",
    "webBuild": "4.81.0",
    "xsecappid": "xhs-pc-web",
    "a1": "19960bf8ec1rjve1ytf5z5tlyot8qivtchg7ucv8k50000165098",
    "webId": "1fd898ad81e2171639c2a1275f474fe8",
    "acw_tc": "0a0bb01117582647916004442e8e6016655037a5fde5fe626c31f131d953ca",
    "websectiga": "a9bdcaed0af874f3a1431e94fbea410e8f738542fbb02df1e8e30c29ef3d91ac",
    "sec_poison_id": "216b254c-8f11-4bd1-8751-49159115491f",
    "web_session": "030037afffa9a30c0e8b9bbbb42f4ac62e426b",
    "loadts": "1758264792144",
    "unread": "{%22ub%22:%2268bc1677000000001d01cd2f%22%2C%22ue%22:%2268c38cac000000001c03cc4f%22%2C%22uc%22:27}",
    "gid": "yjjK8Di08jSfyjjK8DiYdxShSyFVhdyv9i2ukYT291vl9W28YA3h97888yK28jY8WdjW8SWW"
}
url = "https://edith.xiaohongshu.com/api/sns/web/v1/search/querytrending"
params = {
    "source": "UserPage",
    "search_type": "trend",
    "last_query": "",
    "last_query_time": "0",
    "word_request_situation": "FIRST_ENTER",
    "hint_word": "",
    "hint_word_type": "",
    "hint_word_request_id": ""
}
response = requests.get(url, params=params, headers=headers, cookies=cookies)
print(response.text)
