#include <benchmark/benchmark.h>
#include "aes.h"

static void AES128_KeySetUp(benchmark::State& state)
{
   const uint8_t key[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

   for (auto _ : state)
   {
      CAESEncryption objCrypto(key);
   }
}
BENCHMARK(AES128_KeySetUp);

static void AES128_Encryption(benchmark::State& state)
{
   const uint8_t key[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
   const uint8_t input[16] { 0x6a, 0x84, 0x86, 0x7c, 0xd7, 0x7e, 0x12, 0xad,
                             0x07, 0xea, 0x1b, 0xe8, 0x95, 0xc5, 0x3f, 0xa3 };
   CAESEncryption objCrypto(key);
   
   uint8_t crypt[16];
   for (auto _ : state)
   {
      objCrypto.EncryptBlock(input, crypt);
   }
}
BENCHMARK(AES128_Encryption);

static void AES128_Decryption(benchmark::State& state)
{
   const uint8_t key[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
   const uint8_t output[16] { 0x73, 0x22, 0x81, 0xc0, 0xa0, 0xaa, 0xb8, 0xf7, 
                              0xa5, 0x4a, 0x0c, 0x67, 0xa0, 0xc4, 0x5e, 0xcf };
   CAESEncryption objCrypto(key);
   
   uint8_t decrypt[16];
   for (auto _ : state)
   {
      objCrypto.DecryptBlock(output, decrypt);
   }
}
BENCHMARK(AES128_Decryption);

BENCHMARK_MAIN();