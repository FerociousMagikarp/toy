#include "hash/xxhash.hpp"
#include "hash/fnv1a.hpp"
#include "hash/md.hpp"
#include "doctest/doctest.h"

using namespace toy;

TEST_CASE("xxhash64")
{
    static_assert(hash<xxhash64>().update("a").result() == "d24ec4f1a98c6e5b"_hash_hex_64);

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
    CHECK(hash<xxhash64>().update(u8"鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波").result() == "497ad04e6a197d28"_hash_hex_64);
    CHECK(hash<xxhash64>().update(u8"鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波.").result() == "ec19910c59fa74e0"_hash_hex_64);
    CHECK(hash<xxhash64>().update(u8"鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波。").result() == "e073c32b422ea516"_hash_hex_64);

    auto hash_test_1 = hash<xxhash64>(1918516007);
    CHECK(hash_test_1.update("abc").result() == "0cb84df6457c2c35"_hash_hex_64);
    CHECK(hash_test_1.update("defgh").result() == "0e91c6710825c975"_hash_hex_64);
    CHECK(hash_test_1.update("abcdefghijklmnopqrstuvwxyz123456").result() == "bdb6ab26b0eea373"_hash_hex_64);
    CHECK(hash_test_1.update("123456789012345678").result() == "65a900d9fa01554f"_hash_hex_64);
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
    hash_test_1.update("345678901234567890");
    CHECK(hash_test_1.result() == "2fba0860b3d8abfdee05ef2cc87812d2"_hash_hex_128);
}
