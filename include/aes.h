#pragma once
#include <stdint.h>

class CAESEncryption
{
public:
   constexpr CAESEncryption(const uint8_t* Key ) noexcept;
   constexpr void EncryptBlock(const uint8_t* Input, uint8_t* Output) const noexcept;
   constexpr void DecryptBlock(const uint8_t* Input, uint8_t* Output) const noexcept;

private:
   static constexpr size_t block_size = 16;

   // For AES-128
   static constexpr size_t key_length = 16;
   static constexpr size_t num_of_rounds = 10;

   // For AES-192
   //static constexpr size_t key_length = 24;
   //static constexpr size_t num_of_rounds = 12;

   // For AES-256
   //static constexpr size_t key_length = 32;
   //static constexpr size_t num_of_rounds = 14;
   
   uint8_t w[block_size*(num_of_rounds + 1)];
};
