#include "sgx_trts.h"
#include "../Enclave.h"
#include "Enclave_t.h"

/* ecall_array_user_check:
 *   [user_check] parameter does not perfrom copy operations.
 */
void ecall_array_user_check(int arr[4])
{
    if (sgx_is_outside_enclave(arr, 4 * sizeof(int)) != 1)
        abort();

    for (int i = 0; i < 4; i++) {
        assert(arr[i] == i);
        arr[i] = 3 - i;
    }
}

/* ecall_array_in:
 *   arr[] is copied to trusted domain, but modified
 *   results will not be reflected to the untrusted side.
 */
void ecall_array_in(int arr[4])
{
    for (int i = 0; i < 4; i++) {
        assert(arr[i] == i);
        arr[i] = (3 - i);
    }
}

/* ecall_array_out:
 *   arr[] is allocated inside the enclave, and it will be copied
 *   to the untrusted side
 */
void ecall_array_out(int arr[4])
{
    for (int i = 0; i < 4; i++) {
        /* arr is not copied from App */
        assert(arr[i] == 0);
        arr[i] = (3 - i);
    }
}

/* ecall_array_in_out:
 *   arr[] will be allocated inside the enclave, content of arr[] will be copied either.
 *   After ECALL returns, the results will be copied to the outside.
 */
void ecall_array_in_out(int arr[4])
{
    for (int i = 0; i < 4; i++) {
        assert(arr[i] == i);
        arr[i] = (3 - i);
    }
}

/* ecall_array_isary:
 *   [isary] tells Edger8r that user defined 'array_t' is an array type.
 */
void ecall_array_isary(array_t arr)
{
    if (sgx_is_outside_enclave(arr, sizeof(array_t)) != 1)
        abort();

    int n = sizeof(array_t)/sizeof(arr[0]);
    for (int i = 0; i < n; i++) {
        assert(arr[i] == i);
        arr[i] = (n - 1 - i);
    }
}
