#include "doctest/doctest.h"
#include "nanobench.h"

#include <string_view>
#include "hash/xxhash.hpp"
#include "hash/fnv1a.hpp"
#include "hash/md.hpp"
#include "hash/murmurhash.hpp"

using namespace toy;

template <typename H>
void _bench_hash_single(ankerl::nanobench::Bench& bench, const char* name, auto&& content)
{
    bench.run(name, [content]() -> void
    {
        auto val = hash<H>().update(content).result();
        ankerl::nanobench::doNotOptimizeAway(val);
    });
}

template <typename H>
void _bench_hash_single_not_stream(ankerl::nanobench::Bench& bench, const char* name, auto&& content)
{
    bench.run(name, [content]() -> void
    {
        auto val = hash<H>()(content);
        ankerl::nanobench::doNotOptimizeAway(val);
    });
}

void bench_hash(ankerl::nanobench::Bench& bench, auto&& content)
{
    _bench_hash_single<xxhash32>(bench, "xxhash32", content);
    _bench_hash_single<xxhash64>(bench, "xxhash64", content);
    _bench_hash_single<fnv1a_32>(bench, "fnv1a_32", content);
    _bench_hash_single<fnv1a_64>(bench, "fnv1a_64", content);

    // md2 is too slow to benchmark
    // _bench_hash_single<md2>(bench, "md2", content);
    _bench_hash_single<md4>(bench, "md4", content);
    _bench_hash_single<md5>(bench, "md5", content);

    _bench_hash_single_not_stream<murmurhash1>(bench, "murmurhash1", content);
    _bench_hash_single_not_stream<murmurhash2>(bench, "murmurhash2", content);
    _bench_hash_single_not_stream<murmurhash2_64a>(bench, "murmurhash2_64a", content);
    _bench_hash_single_not_stream<murmurhash2_64b>(bench, "murmurhash2_64b", content);
    _bench_hash_single_not_stream<murmurhash2a>(bench, "murmurhash2a", content);
    _bench_hash_single_not_stream<murmurhash3_x86_32>(bench, "murmurhash3_x86_32", content);
    _bench_hash_single_not_stream<murmurhash3_x86_128>(bench, "murmurhash3_x86_128", content);
    _bench_hash_single_not_stream<murmurhash3_x64_128>(bench, "murmurhash3_x64_128", content);
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
