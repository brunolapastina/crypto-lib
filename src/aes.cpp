#include <cstring>
#include "aes.h"


static constexpr uint8_t SBox[256] =
{
   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
   0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
   0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
   0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
   0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
   0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
   0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
   0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
   0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
   0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
   0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
   0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
   0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
   0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
   0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
   0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static constexpr uint8_t SBoxInv[256] =
{
   0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
   0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
   0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
   0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
   0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
   0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
   0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
   0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
   0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
   0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
   0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
   0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
   0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
   0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
   0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
   0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};


constexpr uint8_t SignExpand(uint8_t a) { return static_cast<uint8_t>((static_cast<int8_t>(a) >> 7)); }

/*// This is the generic way to multiply in the Galois field
static __inline uint8_t GMul(uint8_t a, uint8_t b)
{
   uint8_t p = 0;

   for (uint8_t i = 0; i < 8; ++i)
   {
      p = p ^ (a & SignExpand((b & 0x01) << 7));
      b >>= 1;
      a = (a << 1) ^ (0x1b & SignExpand(a));     // x^8 + x^4 + x^3 + x + 1
   }

   return p;
}*/

static constexpr __inline uint8_t GMulBy0x02(const uint8_t b)
{
   return (b << 1) ^ (0x1B & SignExpand(b));
}

static constexpr __inline uint8_t GMulBy0x03(const uint8_t b)
{
   return GMulBy0x02(b) ^ b;
}

static constexpr __inline uint8_t GMulBy0x09(const uint8_t b)
{
   return (b << 3) ^ b ^
          (0x1B & SignExpand(b << 2)) ^
          ((0x1B << 1) & SignExpand(b << 1)) ^
          ((0x1B << 2) & SignExpand(b));
}

static constexpr __inline uint8_t GMulBy0x0B(const uint8_t b)
{
   return (b << 3) ^ (b << 1) ^ b ^
          (0x1B & SignExpand(b << 2)) ^
          ((0x1B << 1) & SignExpand(b << 1)) ^
          (((0x1B << 2)^0x1B) & SignExpand(b));
}

static constexpr __inline uint8_t GMulBy0x0D(const uint8_t b)
{
   return (b << 3) ^ (b << 2) ^ b ^
          (0x1B & SignExpand(b << 2)) ^
          (0x2D & SignExpand(b << 1)) ^
          (0x5A & SignExpand(b     ));
}

static constexpr __inline uint8_t GMulBy0x0E(const uint8_t b)
{
   return (b << 3) ^ (b << 2) ^ (b << 1) ^
          (0x1B & SignExpand(b << 2)) ^
          (0x2D & SignExpand(b << 1)) ^
          (0x41 & SignExpand(b     ));
}


constexpr CAESEncryption::CAESEncryption(const uint8_t* Key) noexcept
{
   uint8_t  Rcon = 0x01;

   std::memcpy( w, Key, key_length );

   for (size_t i = key_length; i < block_size*(num_of_rounds + 1); i += 4)
   {
      if (0 == (i % key_length))
      {
         // RotWord and SBox and Add Rcon
         // Rcon is calculated on the fly as Rcon = GMulBy0x02( Rcon );
         w[i + 0] = w[i - key_length + 0] ^ SBox[w[i - 3]] ^ Rcon;
         w[i + 1] = w[i - key_length + 1] ^ SBox[w[i - 2]];
         w[i + 2] = w[i - key_length + 2] ^ SBox[w[i - 1]];
         w[i + 3] = w[i - key_length + 3] ^ SBox[w[i - 4]];

         Rcon = GMulBy0x02(Rcon);
      }
      else if ((key_length > 24) && (4 == (i % key_length)))
      {
         w[i + 0] = w[i - key_length + 0] ^ SBox[w[i - 4]];
         w[i + 1] = w[i - key_length + 1] ^ SBox[w[i - 3]];
         w[i + 2] = w[i - key_length + 2] ^ SBox[w[i - 2]];
         w[i + 3] = w[i - key_length + 3] ^ SBox[w[i - 1]];
      }
      else
      {
         w[i + 0] = w[i - key_length + 0] ^ w[i - 4];
         w[i + 1] = w[i - key_length + 1] ^ w[i - 3];
         w[i + 2] = w[i - key_length + 2] ^ w[i - 2];
         w[i + 3] = w[i - key_length + 3] ^ w[i - 1];
      }
   }
}

constexpr void CAESEncryption::EncryptBlock(const uint8_t* Input, uint8_t* Output) const noexcept
{
   uint8_t  ss[block_size];
   const uint8_t* wint = (const uint8_t*)&w[0];

   // Set initial state and add the round key
   for (size_t i = 0; i < 16; ++i)
   {
      Output[i] = Input[i] ^ wint[i];
   }

   for (size_t round = 1; round < num_of_rounds; ++round)
   {
      // Do a SubBytes and a ShiftRows
      ss[ 0] = SBox[Output[ 0]];
      ss[ 4] = SBox[Output[ 4]];
      ss[ 8] = SBox[Output[ 8]];
      ss[12] = SBox[Output[12]];

      ss[ 1] = SBox[Output[ 5]];
      ss[ 5] = SBox[Output[ 9]];
      ss[ 9] = SBox[Output[13]];
      ss[13] = SBox[Output[ 1]];

      ss[ 2] = SBox[Output[10]];
      ss[ 6] = SBox[Output[14]];
      ss[10] = SBox[Output[ 2]];
      ss[14] = SBox[Output[ 6]];

      ss[ 3] = SBox[Output[15]];
      ss[ 7] = SBox[Output[ 3]];
      ss[11] = SBox[Output[ 7]];
      ss[15] = SBox[Output[11]];

      // Do a MixColumns with a AddRoundKey
      wint = (const uint8_t*)&w[round*block_size];

      for (size_t l = 0; l < 16; l += 4)
      {
         Output[l + 0] = GMulBy0x02(ss[l + 0]) ^ GMulBy0x03(ss[l + 1]) ^ ss[l + 2] ^ ss[l + 3] ^ wint[l + 0];
         Output[l + 1] = ss[l + 0] ^ GMulBy0x02(ss[l + 1]) ^ GMulBy0x03(ss[l + 2]) ^ ss[l + 3] ^ wint[l + 1];
         Output[l + 2] = ss[l + 0] ^ ss[l + 1] ^ GMulBy0x02(ss[l + 2]) ^ GMulBy0x03(ss[l + 3]) ^ wint[l + 2];
         Output[l + 3] = GMulBy0x03(ss[l + 0]) ^ ss[l + 1] ^ ss[l + 2] ^ GMulBy0x02(ss[l + 3]) ^ wint[l + 3];
      }
   }

   // Do a SubBytes, ShiftRows and a AddRoundKey
   wint = (const uint8_t*)&w[num_of_rounds*block_size];

   Output[ 0] = SBox[Output[ 0]] ^ wint[ 0];
   Output[ 4] = SBox[Output[ 4]] ^ wint[ 4];
   Output[ 8] = SBox[Output[ 8]] ^ wint[ 8];
   Output[12] = SBox[Output[12]] ^ wint[12];

   uint8_t tmp1 = Output[1];
   Output[ 1] = SBox[Output[ 5]] ^ wint[ 1];
   Output[ 5] = SBox[Output[ 9]] ^ wint[ 5];
   Output[ 9] = SBox[Output[13]] ^ wint[ 9];
   Output[13] = SBox[tmp1] ^ wint[13];

   tmp1 = Output[2];
   uint8_t tmp2 = Output[6];
   Output[ 2] = SBox[Output[10]] ^ wint[ 2];
   Output[ 6] = SBox[Output[14]] ^ wint[ 6];
   Output[10] = SBox[tmp1] ^ wint[10];
   Output[14] = SBox[tmp2] ^ wint[14];

   tmp1 = Output[15];
   Output[15] = SBox[Output[11]] ^ wint[15];
   Output[11] = SBox[Output[ 7]] ^ wint[11];
   Output[ 7] = SBox[Output[ 3]] ^ wint[ 7];
   Output[ 3] = SBox[tmp1] ^ wint[3];
}

constexpr void CAESEncryption::DecryptBlock(const uint8_t* Input, uint8_t* Output) const noexcept
{
   uint8_t  ss[block_size];
   const uint8_t* wint = (const uint8_t*)&w[num_of_rounds*block_size];

   // Set initial state and add the round key
   for (size_t i = 0; i < 16; ++i)
   {
      Output[i] = Input[i] ^ wint[i];
   }

   for (size_t round = num_of_rounds - 1; round > 0; --round)
   {
      // Do a InvShiftRows, InvSubBytes and a AddRoundKey
      wint = (const uint8_t*)&w[round*block_size];

      ss[ 0] = SBoxInv[Output[ 0]] ^ wint[ 0];
      ss[ 4] = SBoxInv[Output[ 4]] ^ wint[ 4];
      ss[ 8] = SBoxInv[Output[ 8]] ^ wint[ 8];
      ss[12] = SBoxInv[Output[12]] ^ wint[12];

      ss[13] = SBoxInv[Output[ 9]] ^ wint[13];
      ss[ 9] = SBoxInv[Output[ 5]] ^ wint[ 9];
      ss[ 5] = SBoxInv[Output[ 1]] ^ wint[ 5];
      ss[ 1] = SBoxInv[Output[13]] ^ wint[ 1];

      ss[ 2] = SBoxInv[Output[10]] ^ wint[ 2];
      ss[ 6] = SBoxInv[Output[14]] ^ wint[ 6];
      ss[10] = SBoxInv[Output[ 2]] ^ wint[10];
      ss[14] = SBoxInv[Output[ 6]] ^ wint[14];

      ss[ 3] = SBoxInv[Output[ 7]] ^ wint[ 3];
      ss[ 7] = SBoxInv[Output[11]] ^ wint[ 7];
      ss[11] = SBoxInv[Output[15]] ^ wint[11];
      ss[15] = SBoxInv[Output[ 3]] ^ wint[15];

      // Do a InvMixColumns
      for (size_t l = 0; l < 16; l += 4)
      {
         Output[l + 0] = GMulBy0x0E(ss[l + 0]) ^ GMulBy0x0B(ss[l + 1]) ^ GMulBy0x0D(ss[l + 2]) ^ GMulBy0x09(ss[l + 3]);
         Output[l + 1] = GMulBy0x09(ss[l + 0]) ^ GMulBy0x0E(ss[l + 1]) ^ GMulBy0x0B(ss[l + 2]) ^ GMulBy0x0D(ss[l + 3]);
         Output[l + 2] = GMulBy0x0D(ss[l + 0]) ^ GMulBy0x09(ss[l + 1]) ^ GMulBy0x0E(ss[l + 2]) ^ GMulBy0x0B(ss[l + 3]);
         Output[l + 3] = GMulBy0x0B(ss[l + 0]) ^ GMulBy0x0D(ss[l + 1]) ^ GMulBy0x09(ss[l + 2]) ^ GMulBy0x0E(ss[l + 3]);
      }
   }

   // Do a InvShiftRows, InvSubBytes and than AddRoundKey
   wint = (const uint8_t*)&w[0];

   Output[ 0] = SBoxInv[Output[ 0]] ^ wint[ 0];
   Output[ 4] = SBoxInv[Output[ 4]] ^ wint[ 4];
   Output[ 8] = SBoxInv[Output[ 8]] ^ wint[ 8];
   Output[12] = SBoxInv[Output[12]] ^ wint[12];

   uint8_t tmp1 = Output[13];
   Output[13] = SBoxInv[Output[ 9]] ^ wint[13];
   Output[ 9] = SBoxInv[Output[ 5]] ^ wint[ 9];
   Output[ 5] = SBoxInv[Output[ 1]] ^ wint[ 5];
   Output[ 1] = SBoxInv[tmp1] ^ wint[ 1];

   tmp1 = Output[2];
   uint8_t tmp2 = Output[6];
   Output[ 2] = SBoxInv[Output[10]] ^ wint[ 2];
   Output[ 6] = SBoxInv[Output[14]] ^ wint[ 6];
   Output[10] = SBoxInv[tmp1] ^ wint[10];
   Output[14] = SBoxInv[tmp2] ^ wint[14];

   tmp1 = Output[3];
   Output[ 3] = SBoxInv[Output[ 7]] ^ wint[ 3];
   Output[ 7] = SBoxInv[Output[11]] ^ wint[ 7];
   Output[11] = SBoxInv[Output[15]] ^ wint[11];
   Output[15] = SBoxInv[tmp1] ^ wint[15];
}