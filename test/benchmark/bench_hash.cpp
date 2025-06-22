#include "doctest/doctest.h"
#include "nanobench.h"

#include <string_view>
#include "hash/xxhash.hpp"
#include "hash/fnv1a.hpp"
#include "hash/md.hpp"
#include "hash/murmurhash.hpp"

using namespace toy;


uint64_t MurmurHash64B ( const void * key, int len, uint64_t seed )
{
  const uint32_t m = 0x5bd1e995;
  const int r = 24;

  uint32_t h1 = uint32_t(seed) ^ len;
  uint32_t h2 = uint32_t(seed >> 32);

  const uint32_t * data = (const uint32_t *)key;

  while(len >= 8)
  {
    uint32_t k1 = *data++;
    k1 *= m; k1 ^= k1 >> r; k1 *= m;
    h1 *= m; h1 ^= k1;
    len -= 4;

    uint32_t k2 = *data++;
    k2 *= m; k2 ^= k2 >> r; k2 *= m;
    h2 *= m; h2 ^= k2;
    len -= 4;
  }

  if(len >= 4)
  {
    uint32_t k1 = *data++;
    k1 *= m; k1 ^= k1 >> r; k1 *= m;
    h1 *= m; h1 ^= k1;
    len -= 4;
  }

  switch(len)
  {
  case 3: h2 ^= ((unsigned char*)data)[2] << 16;
  case 2: h2 ^= ((unsigned char*)data)[1] << 8;
  case 1: h2 ^= ((unsigned char*)data)[0];
      h2 *= m;
  };

  h1 ^= h2 >> 18; h1 *= m;
  h2 ^= h1 >> 22; h2 *= m;
  h1 ^= h2 >> 17; h1 *= m;
  h2 ^= h1 >> 19; h2 *= m;

  uint64_t h = h1;

  h = (h << 32) | h2;

  return h;
}



template <typename StrView>
    requires (std::is_same_v<std::decay_t<StrView>, std::string_view>
                || std::is_same_v<std::decay_t<StrView>, std::u8string_view>)
void bench_hash(ankerl::nanobench::Bench& bench, StrView content)
{
    bench.run("xxhash32", [content]() -> void
    {
        auto val = hash<xxhash32>().update(content).result();
        ankerl::nanobench::doNotOptimizeAway(val);
    });

    bench.run("xxhash64", [content]() -> void
    {
        auto val = hash<xxhash64>().update(content).result();
        ankerl::nanobench::doNotOptimizeAway(val);
    });

    bench.run("fnv1a_32", [content]() -> void
    {
        auto val = hash<fnv1a_32>().update(content).result();
        ankerl::nanobench::doNotOptimizeAway(val);
    });

    bench.run("fnv1a_64", [content]() -> void
    {
        auto val = hash<fnv1a_64>().update(content).result();
        ankerl::nanobench::doNotOptimizeAway(val);
    });

    // md2 is too slow to benchmark
    // bench.run("md2", [content]() -> void
    // {
    //     auto val = hash<md2>().update(content).result();
    //     ankerl::nanobench::doNotOptimizeAway(val);
    // });

    bench.run("md4", [content]() -> void
    {
        auto val = hash<md4>().update(content).result();
        ankerl::nanobench::doNotOptimizeAway(val);
    });

    bench.run("md5", [content] () -> void
    {
        auto val = hash<md5>().update(content).result();
        ankerl::nanobench::doNotOptimizeAway(val);
    });

    bench.run("murmurhash1", [content] () -> void
    {
        auto val = hash<murmurhash1>()(content);
        ankerl::nanobench::doNotOptimizeAway(val);
    });
    
    bench.run("murmurhash2", [content] () -> void
    {
        auto val = hash<murmurhash2>()(content);
        ankerl::nanobench::doNotOptimizeAway(val);
    });
 
    bench.run("murmurhash2_64a", [content] () -> void
    {
        auto val = hash<murmurhash2_64a>()(content);
        ankerl::nanobench::doNotOptimizeAway(val);
    });

    bench.run("murmurhash2_64b", [content] () -> void
    {
        auto val = hash<murmurhash2_64b>()(content);
        ankerl::nanobench::doNotOptimizeAway(val);
    });
     
    bench.run("murmurhash2_64b_ori", [content] () -> void
    {
        auto val = MurmurHash64B(content.data(), content.size(), 0);
        ankerl::nanobench::doNotOptimizeAway(val);
    });
}

TEST_CASE("hash")
{
    constexpr std::u8string_view content_long = u8"先帝创业未半而中道崩殂，今天下三分，益州疲弊，此诚危急存亡之秋也。然侍卫之臣不懈于内，忠志之士忘身于外者，盖追先帝之殊遇，欲报之于陛下也。诚宜开张圣听，以光先帝遗德，恢弘志士之气，不宜妄自菲薄，引喻失义，以塞忠谏之路也。宫中府中，俱为一体，陟罚臧否，不宜异同。若有作奸犯科及为忠善者，宜付有司论其刑赏，以昭陛下平明之理，不宜偏私，使内外异法也。侍中、侍郎郭攸之、费祎、董允等，此皆良实，志虑忠纯，是以先帝简拔以遗陛下。愚以为宫中之事，事无大小，悉以咨之，然后施行，必能裨补阙漏，有所广益。将军向宠，性行淑均，晓畅军事，试用于昔日，先帝称之曰能，是以众议举宠为督。愚以为营中之事，悉以咨之，必能使行阵和睦，优劣得所。亲贤臣，远小人，此先汉所以兴隆也；亲小人，远贤臣，此后汉所以倾颓也。先帝在时，每与臣论此事，未尝不叹息痛恨于桓、灵也。侍中、尚书、长史、参军，此悉贞良死节之臣，愿陛下亲之信之，则汉室之隆，可计日而待也。臣本布衣，躬耕于南阳，苟全性命于乱世，不求闻达于诸侯。先帝不以臣卑鄙，猥自枉屈，三顾臣于草庐之中，咨臣以当世之事，由是感激，遂许先帝以驱驰。后值倾覆，受任于败军之际，奉命于危难之间，尔来二十有一年矣。先帝知臣谨慎，故临崩寄臣以大事也。受命以来，夙夜忧叹，恐托付不效，以伤先帝之明，故五月渡泸，深入不毛。今南方已定，兵甲已足，当奖率三军，北定中原，庶竭驽钝，攘除奸凶，兴复汉室，还于旧都。此臣所以报先帝而忠陛下之职分也。至于斟酌损益，进尽忠言，则攸之、祎、允之任也。愿陛下托臣以讨贼兴复之效；不效，则治臣之罪，以告先帝之灵。若无兴德之言，则责攸之、祎、允等之慢，以彰其咎。陛下亦宜自谋，以咨诹善道，察纳雅言，深追先帝遗诏。臣不胜受恩感激。今当远离，临表涕零，不知所言。";

    auto bench = ankerl::nanobench::Bench();
    bench.minEpochIterations(65536)
         .title("hash long content");
    bench_hash(bench, content_long);

    constexpr std::string_view content_short = "abcdefgh";
    bench.title("hash short content");
    bench_hash(bench, content_short);
}
