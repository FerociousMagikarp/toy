#include "hash/xxhash.hpp"
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
