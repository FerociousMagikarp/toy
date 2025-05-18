#include "xxhash.hpp"
#include "doctest/doctest.h"

using namespace toy;

TEST_CASE("xxhash64")
{
    static_assert(hash<xxhash64>().update("a").result() == 0xd24ec4f1a98c6e5b);

    CHECK(hash<xxhash64>().result() == 0xef46db3751d8e999);
    CHECK(hash<xxhash64>(668718853).result() == 0x04e830582a31a119);
    CHECK(hash<xxhash64>().update("a").result() == 0xd24ec4f1a98c6e5b);
    CHECK(hash<xxhash64>(191961062).update("a").result() == 0x6e05ba2887c97977);
    CHECK(hash<xxhash64>().update("abcdefghijklmnopqrstuvwxyz12345").result() == 0x467605901b01d6f6);
    CHECK(hash<xxhash64>(877380273).update("abcdefghijklmnopqrstuvwxyz12345").result() == 0x37b562ec5715e132);
    CHECK(hash<xxhash64>().update("abcdefghijklmnopqrstuvwxyz123456").result() == 0x0022ee3b5a18531b);
    CHECK(hash<xxhash64>().update("abcdefghijklmnopqrstuvwxyz1234567").result() == 0x23bbd16d29353c5f);

    CHECK(hash<xxhash64>().update(u8"测试").result() == 0x403d66837e9bc61f);
    CHECK(hash<xxhash64>(1332727061).update(u8"测试").result() == 0x8b79d3346ad56ea2);
    CHECK(hash<xxhash64>().update(u8"鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波").result() == 0x497ad04e6a197d28);
    CHECK(hash<xxhash64>().update(u8"鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波.").result() == 0xec19910c59fa74e0);
    CHECK(hash<xxhash64>().update(u8"鹅鹅鹅，曲项向天歌。白毛浮绿水，红掌拨清波。").result() == 0xe073c32b422ea516);

    auto hash_test_1 = hash<xxhash64>(1918516007);
    CHECK(hash_test_1.update("abc").result() == 0x0cb84df6457c2c35);
    CHECK(hash_test_1.update("defgh").result() == 0x0e91c6710825c975);
    CHECK(hash_test_1.update("abcdefghijklmnopqrstuvwxyz123456").result() == 0xbdb6ab26b0eea373);
    CHECK(hash_test_1.update("123456789012345678").result() == 0x65a900d9fa01554f);
}
