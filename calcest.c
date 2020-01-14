#include <stdio.h>
#include <math.h>

/*
 * as per scribblemaniac's explanation:
 * t - number of trials
 * n - character count
 * p - probability
 * condition: >=1 matches
 * formula: t = log(1-p)/log(1-1/32^n)
 * comes from:
 *  distribution X~Binomial(t, 1/32^n)
 *  P(X>=1)=p
 */

const double probs[] = { 0.5, 0.8, 0.9, 0.95, 0.99 };
const int charcounts[] = { 2, 3, 4, 5, 6, 7 };

int main(void)
{
	printf("   |");
	for (int i = 0; i < sizeof(probs)/sizeof(probs[0]); ++i) {
		printf(" %11d%% |",(int)((probs[i]*100)+0.5));
	}
	printf("\n");

	printf("---+");
	for (int i = 0; i < sizeof(probs)/sizeof(probs[0]); ++i) {
		printf("--------------+");
	}
	printf("\n");

	for (int i = 0; i < sizeof(charcounts)/sizeof(charcounts[0]); ++i) {
		printf("%2d |",charcounts[i]);
		for (int j = 0; j < sizeof(probs)/sizeof(probs[0]); ++j) {
			double t = log2(1 - probs[j]) / log2(1 - (1 / pow(32,charcounts[i])));
			printf(" %12.0f |",t);
		}
		printf("\n");
	}

	return 0;
}
