#include "hash/xxhash.hpp"
#include "hash/fnv1a.hpp"
#include "hash/md.hpp"
#include "hash/murmurhash.hpp"
#include "doctest/doctest.h"

namespace toy
{
template <std::size_t N>
std::ostream& operator<< (std::ostream& os, const toy::hash_result_value<N>& res)
{
    os << res.to_hexstring().c_str();
    return os;
}
} // namespace toy

using namespace toy;

TEST_CASE("hash_result")
{
    constexpr auto result1 = "550d7456"_hash_hex_32;
    CHECK(result1.to_hexstring() == "550d7456");
    CHECK(hash_result_value<32>{}.to_hexstring() == "00000000");

    constexpr auto result2 = "0022ee3b5a18531b"_hash_hex_64;
    CHECK(result2.to_hexstring() == "0022ee3b5a18531b");
    CHECK(hash_result_value<64>{}.to_hexstring() == "0000000000000000");

    constexpr auto result3 = "12345a"_hash_hex_128;
    CHECK(result3.to_hexstring() == "0000000000000000000000000012345a");
    CHECK(hash_result_value<128>{}.to_hexstring() == "00000000000000000000000000000000");

    constexpr auto result4 = "aa938a3570a512dc3804d443e1f28f957b0204c5"_hash_hex_160;
    CHECK(result4.to_hexstring() == "aa938a3570a512dc3804d443e1f28f957b0204c5");
    CHECK(hash_result_value<160>{}.to_hexstring() == "0000000000000000000000000000000000000000");

    constexpr auto result5 = "24b86f42377911a17a9bab50b2922e66e08a0185a333ae8491034364"_hash_hex_224;
    CHECK(result5.to_hexstring() == "24b86f42377911a17a9bab50b2922e66e08a0185a333ae8491034364");
    CHECK(hash_result_value<224>{}.to_hexstring() == "00000000000000000000000000000000000000000000000000000000");

    constexpr auto result6 = "69aad76eedef353b93a56758050e83019ea861b9a96deef7fd7e77d508cfe785"_hash_hex_256;
    CHECK(result6.to_hexstring() == "69aad76eedef353b93a56758050e83019ea861b9a96deef7fd7e77d508cfe785");
    CHECK(hash_result_value<256>{}.to_hexstring() == "0000000000000000000000000000000000000000000000000000000000000000");

    constexpr auto result7 = "69aad76eedef353b93a56758050e83019ea861b9a96deef7fd7e77d508cfe785"_hash_hex_384;
    CHECK(result7.to_hexstring() == "0000000000000000000000000000000069aad76eedef353b93a56758050e83019ea861b9a96deef7fd7e77d508cfe785");
    CHECK(hash_result_value<384>{}.to_hexstring() == "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

    constexpr auto result8 = "16bc814770dd9767c8a95bc99aa00ee6e6dccc072677482f6bc8d63074bea71c5c1ec36e0ae13a99c1ea7495c9a40627b35e3da73051652062a70fe48634ce12"_hash_hex_512;
    CHECK(result8.to_hexstring() == "16bc814770dd9767c8a95bc99aa00ee6e6dccc072677482f6bc8d63074bea71c5c1ec36e0ae13a99c1ea7495c9a40627b35e3da73051652062a70fe48634ce12");
    CHECK(hash_result_value<512>{}.to_hexstring() == "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
}

TEST_CASE("xxhash32")
{
    static_assert(hash<xxhash32>().update("a").result() == "550d7456"_hash_hex_32);
    static_assert(hash<xxhash32>().update("abcdefghijklmnopqrstuvwxyz1234567").result() == "f3c42fe1"_hash_hex_32);

    CHECK(hash<xxhash32>().result() == "02cc5d05"_hash_hex_32);
    CHECK(hash<xxhash32>(668718853).result() == "252648be"_hash_hex_32);
    CHECK(hash<xxhash32>().update("a").result() == "550d7456"_hash_hex_32);
    CHECK(hash<xxhash32>(191961062).update("a").result() == "814c3d5f"_hash_hex_32);
    CHECK(hash<xxhash32>().update("abcdefghijklmnopqrstuvwxyz12345").result() == "18439a59"_hash_hex_32);
    CHECK(hash<xxhash32>(877380273).update("abcdefghijklmnopqrstuvwxyz12345").result() == "7a4feb5b"_hash_hex_32);
    CHECK(hash<xxhash32>().update("abcdefghijklmnopqrstuvwxyz123456").result() == "865bc9b6"_hash_hex_32);
    CHECK(hash<xxhash32>().update("abcdefghijklmnopqrstuvwxyz1234567").result() == "f3c42fe1"_hash_hex_32);

    CHECK(hash<xxhash32>().update(u8"测试").result() == "bc8c4d48"_hash_hex_32);
    CHECK(hash<xxhash32>(1332727061).update(u8"测试").result() == "82828525"_hash_hex_32);
    CHECK(hash<xxhash32>().update(u8"无使尨也吠").result() == "d72766ef"_hash_hex_32);
    CHECK(hash<xxhash32>().update(u8"鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波").result() == "c451dd7a"_hash_hex_32);
    CHECK(hash<xxhash32>().update(u8"鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波.").result() == "2e0a60ad"_hash_hex_32);
    CHECK(hash<xxhash32>().update(u8"鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波。").result() == "b6c1c166"_hash_hex_32);

    auto hash_test_1 = hash<xxhash32>(1918516007);
    CHECK(hash_test_1.update("abc").result() == "647a2fa5"_hash_hex_32);
    CHECK(hash_test_1.update("defgh").result() == "33ca1196"_hash_hex_32);
    CHECK(hash_test_1.update("").result() == "33ca1196"_hash_hex_32);
    CHECK(hash_test_1.update("abcdefghijklmnopqrstuvwxyz123456").result() == "d64f6183"_hash_hex_32);
    CHECK(hash_test_1.update("123456789012345678").result() == "fc7462d6"_hash_hex_32);

    auto hash_test_2 = hash<xxhash32>();
    CHECK(hash_test_2.update(u8"锄禾日当午,").result() == "e32666aa"_hash_hex_32);
    CHECK(hash_test_2.update(u8"汗滴禾下土.").result() == "38e3c050"_hash_hex_32);
    CHECK(hash_test_2.update(u8"谁知盘中餐,").result() == "9b4ae119"_hash_hex_32);
    CHECK(hash_test_2.update(u8"粒粒皆辛苦.").result() == "65db2f60"_hash_hex_32);
}

TEST_CASE("xxhash64")
{
    static_assert(hash<xxhash64>().update("a").result() == "d24ec4f1a98c6e5b"_hash_hex_64);
    static_assert(hash<xxhash64>().update("abcdefghijklmnopqrstuvwxyz1234567").result() == "23bbd16d29353c5f"_hash_hex_64);

    CHECK(hash<xxhash64>().result() == "ef46db3751d8e999"_hash_hex_64);
    CHECK(hash<xxhash64>(668718853).result() == "04e830582a31a119"_hash_hex_64);
    CHECK(hash<xxhash64>().update("a").result() == "d24ec4f1a98c6e5b"_hash_hex_64);
    CHECK(hash<xxhash64>(191961062).update("a").result() == "6e05ba2887c97977"_hash_hex_64);
    CHECK(hash<xxhash64>().update("abcdefghijklmnopqrstuvwxyz12345").result() == "467605901b01d6f6"_hash_hex_64);
    CHECK(hash<xxhash64>(877380273).update("abcdefghijklmnopqrstuvwxyz12345").result() == "37b562ec5715e132"_hash_hex_64);
    CHECK(hash<xxhash64>().update("abcdefghijklmnopqrstuvwxyz123456").result() == "0022ee3b5a18531b"_hash_hex_64);
    CHECK(hash<xxhash64>().update("abcdefghijklmnopqrstuvwxyz1234567").result() == "23bbd16d29353c5f"_hash_hex_64);

    CHECK(hash<xxhash64>().update(u8"测试").result() == "403d66837e9bc61f"_hash_hex_64);
    CHECK(hash<xxhash64>(1332727061).update(u8"测试").result() == "8b79d3346ad56ea2"_hash_hex_64);
    CHECK(hash<xxhash64>().update(u8"无使尨也吠").result() == "a4800f1d00dd325b"_hash_hex_64);
    CHECK(hash<xxhash64>().update(u8"鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波").result() == "497ad04e6a197d28"_hash_hex_64);
    CHECK(hash<xxhash64>().update(u8"鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波.").result() == "ec19910c59fa74e0"_hash_hex_64);
    CHECK(hash<xxhash64>().update(u8"鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波。").result() == "e073c32b422ea516"_hash_hex_64);

    auto hash_test_1 = hash<xxhash64>(1918516007);
    CHECK(hash_test_1.update("abc").result() == "0cb84df6457c2c35"_hash_hex_64);
    CHECK(hash_test_1.update("defgh").result() == "0e91c6710825c975"_hash_hex_64);
    CHECK(hash_test_1.update("").result() == "0e91c6710825c975"_hash_hex_64);
    CHECK(hash_test_1.update("abcdefghijklmnopqrstuvwxyz123456").result() == "bdb6ab26b0eea373"_hash_hex_64);
    CHECK(hash_test_1.update("123456789012345678").result() == "65a900d9fa01554f"_hash_hex_64);

    auto hash_test_2 = hash<xxhash64>();
    CHECK(hash_test_2.update(u8"锄禾日当午,").result() == "5898901694302e88"_hash_hex_64);
    CHECK(hash_test_2.update(u8"汗滴禾下土.").result() == "3e0a8dd7c2e943cc"_hash_hex_64);
    CHECK(hash_test_2.update(u8"谁知盘中餐,").result() == "d2d9b500123a1c3d"_hash_hex_64);
    CHECK(hash_test_2.update(u8"粒粒皆辛苦.").result() == "2b87a1b6cbc599e6"_hash_hex_64);
}

TEST_CASE("fnv1a_32")
{
    static_assert(hash<fnv1a_32>().update("a").result() == "e40c292c"_hash_hex_32);

    CHECK(hash<fnv1a_32>().update("a").result() == "e40c292c"_hash_hex_32);
    CHECK(hash<fnv1a_32>().update(u8"测试").result() == "f78149cf"_hash_hex_32);

    CHECK(hash<fnv1a_32>().update("a").update("a").result() == hash<fnv1a_32>().update("aa").result());
}

TEST_CASE("fnv1a_64")
{
    static_assert(hash<fnv1a_64>().update("a").result() == "af63dc4c8601ec8c"_hash_hex_64);

    CHECK(hash<fnv1a_64>().update("a").result() == "af63dc4c8601ec8c"_hash_hex_64);
    CHECK(hash<fnv1a_64>().update(u8"测试").result() == "4655115154662b2f"_hash_hex_64);

    CHECK(hash<fnv1a_64>().update("a").update("a").result() == hash<fnv1a_64>().update("aa").result());
}

TEST_CASE("md2")
{
    static_assert(hash<md2>().update("a").result() == "32ec01ec4a6dac72c0ab96fb34c0b5d1"_hash_hex_128);
    static_assert(hash<md2>().update("12345678901234567890123456789012345678901234567890123456789012345678901234567890").result() == "d5976f79d83d3a0dc9806c3c66f3efd8"_hash_hex_128);

    CHECK(hash<md2>().update("").result() == "8350e5a3e24c153df2275c9f80692773"_hash_hex_128);
    CHECK(hash<md2>().update("a").result() == "32ec01ec4a6dac72c0ab96fb34c0b5d1"_hash_hex_128);
    CHECK(hash<md2>().update("abc").result() == "da853b0d3f88d99b30283a69e6ded6bb"_hash_hex_128);
    CHECK(hash<md2>().update("message digest").result() == "ab4f496bfb2a530b219ff33031fe06b0"_hash_hex_128);
    CHECK(hash<md2>().update("abcdefghijklmnopqrstuvwxyz").result() == "4e8ddff3650292ab5a4108c3aa47940b"_hash_hex_128);
    CHECK(hash<md2>().update("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").result() == "da33def2a42df13975352846c30338cd"_hash_hex_128);
    CHECK(hash<md2>().update("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789,.").result() == "d12f3647dff5c86f003bb3014f8f18eb"_hash_hex_128);
    CHECK(hash<md2>().update("12345678901234567890123456789012345678901234567890123456789012345678901234567890").result() == "d5976f79d83d3a0dc9806c3c66f3efd8"_hash_hex_128);

    CHECK(hash<md2>().update(u8"测试").result() == "a8d6fb5a5735c294e9fb41ba8ae98eaf"_hash_hex_128);

    auto hash_test_1 = hash<md2>();
    CHECK(hash_test_1.result() == "8350e5a3e24c153df2275c9f80692773"_hash_hex_128);
    hash_test_1.update("a");
    CHECK(hash_test_1.result() == "32ec01ec4a6dac72c0ab96fb34c0b5d1"_hash_hex_128);
    hash_test_1.update("bc");
    CHECK(hash_test_1.result() == "da853b0d3f88d99b30283a69e6ded6bb"_hash_hex_128);
    hash_test_1.update("defghijklmnopqrstuvwxyz");
    CHECK(hash_test_1.result() == "4e8ddff3650292ab5a4108c3aa47940b"_hash_hex_128);
    hash_test_1.update("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    CHECK(hash_test_1.result() == "c686ef70ed97e759bf217e4befd7fbd8"_hash_hex_128);
    hash_test_1.update("");
    CHECK(hash_test_1.result() == "c686ef70ed97e759bf217e4befd7fbd8"_hash_hex_128);
    hash_test_1.update("345678901234567890");
    CHECK(hash_test_1.result() == "ae3a12d8f20a4f020a4581942135d5ee"_hash_hex_128);
}

TEST_CASE("md4")
{
    static_assert(hash<md4>().update("a").result() == "bde52cb31de33e46245e05fbdbd6fb24"_hash_hex_128);
    static_assert(hash<md4>().update("12345678901234567890123456789012345678901234567890123456789012345678901234567890").result() == "e33b4ddc9c38f2199c3e7b164fcc0536"_hash_hex_128);

    CHECK(hash<md4>().update("").result() == "31d6cfe0d16ae931b73c59d7e0c089c0"_hash_hex_128);
    CHECK(hash<md4>().update("a").result() == "bde52cb31de33e46245e05fbdbd6fb24"_hash_hex_128);
    CHECK(hash<md4>().update("abc").result() == "a448017aaf21d8525fc10ae87aa6729d"_hash_hex_128);
    CHECK(hash<md4>().update("message digest").result() == "d9130a8164549fe818874806e1c7014b"_hash_hex_128);
    CHECK(hash<md4>().update("abcdefghijklmnopqrstuvwxyz").result() == "d79e1c308aa5bbcdeea8ed63df412da9"_hash_hex_128);
    CHECK(hash<md4>().update("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").result() == "043f8582f241db351ce627e153e7f0e4"_hash_hex_128);
    CHECK(hash<md4>().update("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789,.").result() == "993c38901c59d324a64ec2d4c9a1b091"_hash_hex_128);
    CHECK(hash<md4>().update("12345678901234567890123456789012345678901234567890123456789012345678901234567890").result() == "e33b4ddc9c38f2199c3e7b164fcc0536"_hash_hex_128);

    CHECK(hash<md4>().update(u8"测试").result() == "1968504f74e56db119877599cf979e09"_hash_hex_128);

    auto hash_test_1 = hash<md4>();
    CHECK(hash_test_1.result() == "31d6cfe0d16ae931b73c59d7e0c089c0"_hash_hex_128);
    hash_test_1.update("a");
    CHECK(hash_test_1.result() == "bde52cb31de33e46245e05fbdbd6fb24"_hash_hex_128);
    hash_test_1.update("bc");
    CHECK(hash_test_1.result() == "a448017aaf21d8525fc10ae87aa6729d"_hash_hex_128);
    hash_test_1.update("defghijklmnopqrstuvwxyz");
    CHECK(hash_test_1.result() == "d79e1c308aa5bbcdeea8ed63df412da9"_hash_hex_128);
    hash_test_1.update("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    CHECK(hash_test_1.result() == "86ef62be22e4f920a6078a9faeef9f04"_hash_hex_128);
    hash_test_1.update("");
    CHECK(hash_test_1.result() == "86ef62be22e4f920a6078a9faeef9f04"_hash_hex_128);
    hash_test_1.update("345678901234567890");
    CHECK(hash_test_1.result() == "390c88ba9e2475e3fb58fd080d7517ca"_hash_hex_128);
}

TEST_CASE("md5")
{
    static_assert(hash<md5>().update("a").result() == "0cc175b9c0f1b6a831c399e269772661"_hash_hex_128);
    static_assert(hash<md5>().update("12345678901234567890123456789012345678901234567890123456789012345678901234567890").result() == "57edf4a22be3c955ac49da2e2107b67a"_hash_hex_128);

    CHECK(hash<md5>().update("").result() == "d41d8cd98f00b204e9800998ecf8427e"_hash_hex_128);
    CHECK(hash<md5>().update("a").result() == "0cc175b9c0f1b6a831c399e269772661"_hash_hex_128);
    CHECK(hash<md5>().update("abc").result() == "900150983cd24fb0d6963f7d28e17f72"_hash_hex_128);
    CHECK(hash<md5>().update("message digest").result() == "f96b697d7cb7938d525a2f31aaf161d0"_hash_hex_128);
    CHECK(hash<md5>().update("abcdefghijklmnopqrstuvwxyz").result() == "c3fcd3d76192e4007dfb496cca67e13b"_hash_hex_128);
    CHECK(hash<md5>().update("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").result() == "d174ab98d277d9f5a5611c2c9f419d9f"_hash_hex_128);
    CHECK(hash<md5>().update("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789,.").result() == "8399a3d9447c3d2e7856d1d21d3e7ade"_hash_hex_128);
    CHECK(hash<md5>().update("12345678901234567890123456789012345678901234567890123456789012345678901234567890").result() == "57edf4a22be3c955ac49da2e2107b67a"_hash_hex_128);

    CHECK(hash<md5>().update(u8"测试").result() == "db06c78d1e24cf708a14ce81c9b617ec"_hash_hex_128);

    auto hash_test_1 = hash<md5>();
    CHECK(hash_test_1.result() == "d41d8cd98f00b204e9800998ecf8427e"_hash_hex_128);
    hash_test_1.update("a");
    CHECK(hash_test_1.result() == "0cc175b9c0f1b6a831c399e269772661"_hash_hex_128);
    hash_test_1.update("bc");
    CHECK(hash_test_1.result() == "900150983cd24fb0d6963f7d28e17f72"_hash_hex_128);
    hash_test_1.update("defghijklmnopqrstuvwxyz");
    CHECK(hash_test_1.result() == "c3fcd3d76192e4007dfb496cca67e13b"_hash_hex_128);
    hash_test_1.update("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789");
    CHECK(hash_test_1.result() == "76658de2ac7d406f93dfbe8bb6d9f549"_hash_hex_128);
    hash_test_1.update("");
    CHECK(hash_test_1.result() == "76658de2ac7d406f93dfbe8bb6d9f549"_hash_hex_128);
    hash_test_1.update("345678901234567890");
    CHECK(hash_test_1.result() == "2fba0860b3d8abfdee05ef2cc87812d2"_hash_hex_128);
}

TEST_CASE("murmurhash1")
{
    static_assert(hash<murmurhash1>()("a") == "872d28c5"_hash_hex_32);

    CHECK(hash<murmurhash1>(61755476)("") == "74d531ef"_hash_hex_32);
    CHECK(hash<murmurhash1>()("a") == "872d28c5"_hash_hex_32);
    CHECK(hash<murmurhash1>()("1234") == "f12e8bad"_hash_hex_32);
    CHECK(hash<murmurhash1>()("abcdefghi") == "3a97264c"_hash_hex_32);
    CHECK(hash<murmurhash1>()("abcdefghij") == "912e647a"_hash_hex_32);
    CHECK(hash<murmurhash1>()("abcdefghijk") == "9b770060"_hash_hex_32);

    CHECK(hash<murmurhash1>()(u8"测试") == "fcad7be1"_hash_hex_32);
    CHECK(hash<murmurhash1>(900812297)(u8"结果是多少") == "5bb709b8"_hash_hex_32);
}

TEST_CASE("murmurhash2")
{
    static_assert(hash<murmurhash2>()("a") == "92685f5e"_hash_hex_32);

    CHECK(hash<murmurhash2>(61755476)("") == "46b0f07e"_hash_hex_32);
    CHECK(hash<murmurhash2>()("a") == "92685f5e"_hash_hex_32);
    CHECK(hash<murmurhash2>()("1234") == "018492f9"_hash_hex_32);
    CHECK(hash<murmurhash2>()("abcdefghi") == "f0319aa7"_hash_hex_32);
    CHECK(hash<murmurhash2>()("abcdefghij") == "4b09c914"_hash_hex_32);
    CHECK(hash<murmurhash2>()("abcdefghijk") == "4a7439a6"_hash_hex_32);

    CHECK(hash<murmurhash2>()(u8"测试") == "94fa7981"_hash_hex_32);
    CHECK(hash<murmurhash2>(900812297)(u8"结果是多少") == "79928a88"_hash_hex_32);
}

TEST_CASE("murmurhash2_64a")
{
    static_assert(hash<murmurhash2_64a>()("a") == "071717d2d36b6b11"_hash_hex_64);

    CHECK(hash<murmurhash2_64a>(61755476)("") == "42a0e7753c25b1a5"_hash_hex_64);
    CHECK(hash<murmurhash2_64a>()("a") == "071717d2d36b6b11"_hash_hex_64);
    CHECK(hash<murmurhash2_64a>()("1234") == "92b7977746710c51"_hash_hex_64);
    CHECK(hash<murmurhash2_64a>()("abcdefghi") == "c9b9d84356146ac2"_hash_hex_64);
    CHECK(hash<murmurhash2_64a>()("abcdefghij") == "a33f0dbf245bcb51"_hash_hex_64);
    CHECK(hash<murmurhash2_64a>()("abcdefghijk") == "feff07a18c726536"_hash_hex_64);
    CHECK(hash<murmurhash2_64a>()("abcdefghijkl") == "a24066d5378b01bb"_hash_hex_64);
    CHECK(hash<murmurhash2_64a>()("abcdefghijklm") == "e126e825baaba665"_hash_hex_64);
    CHECK(hash<murmurhash2_64a>()("abcdefghijklmn") == "9da2538e559887e9"_hash_hex_64);
    CHECK(hash<murmurhash2_64a>()("abcdefghijklmno") == "fdaac8a629dcd46a"_hash_hex_64);

    CHECK(hash<murmurhash2_64a>()(u8"测试") == "21ac04a1894efdbf"_hash_hex_64);
    CHECK(hash<murmurhash2_64a>(900812297)(u8"结果是多少") == "deb3133cffb5d046"_hash_hex_64);
}

TEST_CASE("murmurhash2_64b")
{
    static_assert(hash<murmurhash2_64b>()("a") == "716e41e3dff50b85"_hash_hex_64);

    CHECK(hash<murmurhash2_64b>(61755476)("") == "c9e1ca157a93477c"_hash_hex_64);
    CHECK(hash<murmurhash2_64b>()("a") == "716e41e3dff50b85"_hash_hex_64);
    CHECK(hash<murmurhash2_64b>()("1234") == "dd72c9660e2c94fe"_hash_hex_64);
    CHECK(hash<murmurhash2_64b>()("abcdefghi") == "c7f119fa4f515136"_hash_hex_64);
    CHECK(hash<murmurhash2_64b>()("abcdefghij") == "dbff398b66d28e58"_hash_hex_64);
    CHECK(hash<murmurhash2_64b>()("abcdefghijk") == "4c34396965f1d3d"_hash_hex_64);
    CHECK(hash<murmurhash2_64b>()("abcdefghijkl") == "9310dfec0a0bab90"_hash_hex_64);
    CHECK(hash<murmurhash2_64b>()("abcdefghijklm") == "3bcce82899a6d9a6"_hash_hex_64);
    CHECK(hash<murmurhash2_64b>()("abcdefghijklmn") == "6c7df090a8541296"_hash_hex_64);
    CHECK(hash<murmurhash2_64b>()("abcdefghijklmno") == "69e7f39723d7f52a"_hash_hex_64);

    CHECK(hash<murmurhash2_64b>()(u8"测试") == "de5f4e8a9f6d0566"_hash_hex_64);
    CHECK(hash<murmurhash2_64b>(900812297)(u8"结果是多少") == "e8316082e2cab316"_hash_hex_64);
}

TEST_CASE("murmurhash2a")
{
    static_assert(hash<murmurhash2a>()("a") == "803888b"_hash_hex_32);
    static_assert(hash<murmurhash2a>()("abcdefghijk") == "c233757e"_hash_hex_32);

    CHECK(hash<murmurhash2a>(61755476)("") == "e6d91157"_hash_hex_32);
    CHECK(hash<murmurhash2a>()("a") == "803888b"_hash_hex_32);
    CHECK(hash<murmurhash2a>()("1234") == "905970e4"_hash_hex_32);
    CHECK(hash<murmurhash2a>()("abcdefghi") == "c6578446"_hash_hex_32);
    CHECK(hash<murmurhash2a>()("abcdefghij") == "3240af5e"_hash_hex_32);
    CHECK(hash<murmurhash2a>()("abcdefghijk") == "c233757e"_hash_hex_32);

    CHECK(hash<murmurhash2a>()(u8"测试") == "d0602e8a"_hash_hex_32);
    CHECK(hash<murmurhash2a>(900812297)(u8"结果是多少") == "f158f6fa"_hash_hex_32);

    auto hash_test = hash<murmurhash2a>();
    hash_test.update("a");
    CHECK(hash_test.result() == "803888b"_hash_hex_32);
    hash_test.update("bcdefghi");
    CHECK(hash_test.result() == "c6578446"_hash_hex_32);
    hash_test.update("jk");
    CHECK(hash_test.result() == "c233757e"_hash_hex_32);
}

TEST_CASE("murmurhash3_x86_32")
{
    static_assert(hash<murmurhash3_x86_32>()("a") == "3c2569b2"_hash_hex_32);
    static_assert(hash<murmurhash3_x86_32>()("abcdefghijk") == "5f3b25df"_hash_hex_32);

    CHECK(hash<murmurhash3_x86_32>(61755476)("") == "c418f5e4"_hash_hex_32);
    CHECK(hash<murmurhash3_x86_32>()("a") == "3c2569b2"_hash_hex_32);
    CHECK(hash<murmurhash3_x86_32>()("1234") == "721c5dc3"_hash_hex_32);
    CHECK(hash<murmurhash3_x86_32>()("abcdefghi") == "421406f0"_hash_hex_32);
    CHECK(hash<murmurhash3_x86_32>()("abcdefghij") == "88927791"_hash_hex_32);
    CHECK(hash<murmurhash3_x86_32>()("abcdefghijk") == "5f3b25df"_hash_hex_32);

    CHECK(hash<murmurhash3_x86_32>()(u8"测试") == "fe75a838"_hash_hex_32);
    CHECK(hash<murmurhash3_x86_32>(900812297)(u8"结果是多少") == "c8fbcc27"_hash_hex_32);

    auto hash_test = hash<murmurhash3_x86_32>();
    hash_test.update("a");
    CHECK(hash_test.result() == "3c2569b2"_hash_hex_32);
    hash_test.update("bcdefghi");
    CHECK(hash_test.result() == "421406f0"_hash_hex_32);
    hash_test.update("jk");
    CHECK(hash_test.result() == "5f3b25df"_hash_hex_32);
}

TEST_CASE("murmurhash3_x86_128")
{
    static_assert(hash<murmurhash3_x86_128>()("a") == "5556b01b5556b01b5556b01ba794933c"_hash_hex_128);
    static_assert(hash<murmurhash3_x86_128>()("abcdefghijk") == "bd5e975782fef12dca1f111ea0c8c9dd"_hash_hex_128);

    CHECK(hash<murmurhash3_x86_128>(61755476)("") == "2be55f702be55f702be55f7039cb536c"_hash_hex_128);
    CHECK(hash<murmurhash3_x86_128>()("a") == "5556b01b5556b01b5556b01ba794933c"_hash_hex_128);
    CHECK(hash<murmurhash3_x86_128>()("1234") == "2eaa32ce2eaa32ce2eaa32ce4adf644d"_hash_hex_128);
    CHECK(hash<murmurhash3_x86_128>()("abcdefghi") == "dd94417c14d27d102206596fad058c1c"_hash_hex_128);
    CHECK(hash<murmurhash3_x86_128>()("abcdefghij") == "692ff17fc792aa2a9a37900ef5d92ea7"_hash_hex_128);
    CHECK(hash<murmurhash3_x86_128>()("abcdefghijk") == "bd5e975782fef12dca1f111ea0c8c9dd"_hash_hex_128);
    CHECK(hash<murmurhash3_x86_128>()("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") == "12720c3207ed382948ddf7322962d6e7"_hash_hex_128);
    CHECK(hash<murmurhash3_x86_128>()("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.") == "1b7258f3ab3daf9521188b0d76865867"_hash_hex_128);
    CHECK(hash<murmurhash3_x86_128>()("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,") == "3ed33b86c817f76ad9c666a41c50629d"_hash_hex_128);

    CHECK(hash<murmurhash3_x86_128>()(u8"测试") == "3c4edb603c4edb605b39801c441c0b05"_hash_hex_128);
    CHECK(hash<murmurhash3_x86_128>(900812297)(u8"结果是多少") == "309f18204f67004ab06b6fe1a027d1c8"_hash_hex_128);

    auto hash_test = hash<murmurhash3_x86_128>();
    hash_test.update("a");
    CHECK(hash_test.result() == "5556b01b5556b01b5556b01ba794933c"_hash_hex_128);
    hash_test.update("bcdefghi");
    CHECK(hash_test.result() == "dd94417c14d27d102206596fad058c1c"_hash_hex_128);
    hash_test.update("jk");
    CHECK(hash_test.result() == "bd5e975782fef12dca1f111ea0c8c9dd"_hash_hex_128);
    hash_test.update("lmnop");
    CHECK(hash_test.result() == "d193ba45e4ce8b2190b912569fd27627"_hash_hex_128);
    hash_test.update("qr");
    CHECK(hash_test.result() == "d941585828719e6a961d29daa09354aa"_hash_hex_128);
}

TEST_CASE("murmurhash3_x64_128")
{
    static_assert(hash<murmurhash3_x64_128>()("a") == "e6b53a48510e895a85555565f6597889"_hash_hex_128);
    static_assert(hash<murmurhash3_x64_128>()("abcdefghijk") == "bb7c31e2455ae771a895d0b8df789d02"_hash_hex_128);

    CHECK(hash<murmurhash3_x64_128>(61755476)("") == "e493b454e1851d7feb53992bb4f02004"_hash_hex_128);
    CHECK(hash<murmurhash3_x64_128>()("a") == "e6b53a48510e895a85555565f6597889"_hash_hex_128);
    CHECK(hash<murmurhash3_x64_128>()("1234") == "341e8bd92437fda50897364d218fe7b4"_hash_hex_128);
    CHECK(hash<murmurhash3_x64_128>()("abcdefghi") == "79b53df5b741e0330547c0cff13c7964"_hash_hex_128);
    CHECK(hash<murmurhash3_x64_128>()("abcdefghij") == "a24d85dc8c651ac9b6c15b0d772f8c99"_hash_hex_128);
    CHECK(hash<murmurhash3_x64_128>()("abcdefghijk") == "bb7c31e2455ae771a895d0b8df789d02"_hash_hex_128);
    CHECK(hash<murmurhash3_x64_128>()("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") == "cbadd23ca9ceb9bc49991f325fd73e3b"_hash_hex_128);
    CHECK(hash<murmurhash3_x64_128>()("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.") == "2f009dca7f55ce98295c72d83c1da6ce"_hash_hex_128);
    CHECK(hash<murmurhash3_x64_128>()("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,") == "067a0c4f5416c70ff1f29eec7d73c558"_hash_hex_128);

    CHECK(hash<murmurhash3_x64_128>()(u8"测试") == "2cb4def0e0e0bd5725764ef0e506f500"_hash_hex_128);
    CHECK(hash<murmurhash3_x64_128>(900812297)(u8"结果是多少") == "304a619fe1e1a8dd2e8acfeca83091d3"_hash_hex_128);

    auto hash_test = hash<murmurhash3_x64_128>();
    hash_test.update("a");
    CHECK(hash_test.result() == "e6b53a48510e895a85555565f6597889"_hash_hex_128);
    hash_test.update("bcdefghi");
    CHECK(hash_test.result() == "79b53df5b741e0330547c0cff13c7964"_hash_hex_128);
    hash_test.update("jk");
    CHECK(hash_test.result() == "bb7c31e2455ae771a895d0b8df789d02"_hash_hex_128);
    hash_test.update("lmnop");
    CHECK(hash_test.result() == "4333d695b331eb1ac4ca3ca3224cb723"_hash_hex_128);
    hash_test.update("qr");
    CHECK(hash_test.result() == "71d4a8295a00c76b77f08cec907f8a50"_hash_hex_128);
}
