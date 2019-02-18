#include <cstdio>
#include <gtest/gtest.h>
#include "aes.h"
#include "AESAVS.h"


class AES128EncDecTest : public ::testing::TestWithParam<AES128TestCase>
{
};

TEST_P(AES128EncDecTest, Encryption)
{
   CAESEncryption objCrypto(GetParam().Key);

   uint8_t crypt[16];
   objCrypto.EncryptBlock(GetParam().Input, crypt);
   ASSERT_EQ( 0, memcmp(GetParam().Output, crypt, 16) );
}

TEST_P(AES128EncDecTest, Decryption)
{
   CAESEncryption objCrypto(GetParam().Key);

   uint8_t decrypt[16];
   objCrypto.DecryptBlock(GetParam().Output, decrypt);
   ASSERT_EQ( 0, memcmp(GetParam().Input, decrypt, 16) );
}

INSTANTIATE_TEST_CASE_P ( GFSboxKnowAnswer,  AES128EncDecTest, ::testing::ValuesIn(AppendixB_128) );
INSTANTIATE_TEST_CASE_P ( KeySboxKnowAnswer, AES128EncDecTest, ::testing::ValuesIn(AppendixC_128) );
INSTANTIATE_TEST_CASE_P ( VarTxtKnowAnswer,  AES128EncDecTest, ::testing::ValuesIn(AppendixD_128) );
INSTANTIATE_TEST_CASE_P ( VarKeyKnowAnswer,  AES128EncDecTest, ::testing::ValuesIn(AppendixE_128) );

int main(int argc, char **argv)
{
   testing::InitGoogleTest(&argc, argv);
   return RUN_ALL_TESTS();
}