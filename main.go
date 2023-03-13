package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	args := os.Args
	argc := len(args)
	maxLen := 6
	// by default, use OpenSSL EVP_sha256 which corresponds to JSON HS256 (HMAC-SHA256)
	defaultHmacAlg := "sha256"
	alphabet := "eariotnslcudpmhgbfywkvxzjqEARIOTNSLCUDPMHGBFYWKVXZJQ0123456789"

	if argc < 2 {
		fmt.Printf("%s <token> [alphabet] [max_len] [hmac_alg]\nDefaults: alphabet=%s, max_len=%d, hmac_alg=%s\n", args[0], alphabet, maxLen, defaultHmacAlg)
		return
	}

	// Get the token
	jwt := args[1]

	if argc > 2 {
		alphabet = args[2]
	}
	if argc > 3 {
		i3, err := strconv.Atoi(args[3])
		if err != nil {
			fmt.Printf("Invalid max_len value %s (%d), defaults to %d\n", args[3], i3, maxLen)
			return
		}
		maxLen = i3
	}

	if argc > 4 {
		evp_md := EVP_get_digestbyname(args[4])
		if evp_md == nil {
			fmt.Printf("Unknown message digest %s, will use default %s\n", args[4], defaultHmacAlg)
		}
	} else {
		evp_md = nil
	}

	if evp_md == nil {
		evp_md = EVP_get_digestbyname(defaultHmacAlg)
		if evp_md == nil {
			fmt.Printf("Cannot initialize the default message digest %s, aborting\n", defaultHmacAlg)
			return
		}
	}

	g_alphabet_len := len(alphabet)

	// Split the JWT into header, payload and signature
	splited:=strings.Split(jwt, ".")
	g_header_b64 := splited[0]
	g_payload_b64 := splited[1]
	g_signature_b64 :=splited[2]
	g_header_b64_len := len(g_header_b64);
	g_payload_b64_len := len(g_payload_b64);
	g_signature_b64_len := len(g_signature_b64);

	// Recreate the part that is used to create the signature
	// Since it will always be the same
	//g_to_encrypt_len := g_header_b64_len + 1 + g_payload_b64_len;
	//g_to_encrypt := (unsigned char *) malloc(g_to_encrypt_len + 1);
	//sprintf((char *) g_to_encrypt, "%s.%s", g_header_b64, g_payload_b64);

	// Decode the signature

	g_signature,_ := base64.StdEncoding.DecodeString(g_signature_b64)



	//struct s_thread_data *pointers_data[g_alphabet_len];

		for i := 0; i < g_alphabet_len; i++ {
		pointers_data[i] = malloc(sizeof(struct s_thread_data));
		init_thread_data(pointers_data[i], g_alphabet[i], max_len, evp_md);
		pthread_create(&tid[i], NULL, (void *(*)(void *)) brute_sequential, pointers_data[i]);
	}

		for  i := 0; i < g_alphabet_len; i++{
				pthread_join(tid[i], NULL);
			}
		if (g_found_secret == NULL){
		fmt.Print("No solution found :-(\n");
		}  else{
			fmt.Printf("Secret is \"%s\"\n", g_found_secret);
		}
	}

/*func usage(cmd string, alphabet string, maxLen int, hmacAlg string) {
	fmt.Printf("%s <token> [alphabet] [max_len] [hmac_alg]\nDefaults: alphabet=%s, max_len=%d, hmac_alg=%s\n", cmd, alphabet, maxLen, hmacAlg)
}
*/
	type s_thread_data struct {
		const EVP_MD *g_evp_md; // The hash function to apply the HMAC to

		// Holds the computed signature at each iteration to compare it with the original
		// signature
		unsigned char *g_result;
		unsigned int g_result_len;

		char *g_buffer; // Holds the secret being constructed

		char starting_letter; // Each thread is assigned a first letter
		size_t max_len; // And tries combinations up to a certain length
	};
