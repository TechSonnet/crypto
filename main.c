int test_sha3_512();
int test_rc4();
int test_zuc_256();
int test_trivium();

int main(void) {

   test_sha3_512();
   test_rc4();
   test_zuc_256();
   test_trivium();

   return 0;
}