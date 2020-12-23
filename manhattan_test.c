#include "manhattan.h"
#include <stdlib.h>
#include <stdio.h>

void func(double* array, int rows, int cols)
{
    int i, j;

    for (i=0; i<rows; i++)
    {
        for (j=0; j<cols; j++)
        {
            array[i*cols+j]=i*j;
        }
    }
}


int main() {
    int rows = 3, cols = 3;
    double *x;
    x = malloc(rows * cols * sizeof *x);
//    score_keystrokes(double *fit_vectors, int fit_vectors_num, int features_number, double *target_vector)
    func(x, rows, cols);
    print_array(x, rows, cols);
    double *target;
    target = malloc(cols * sizeof *target);
    printf("target :\n");
    for (int i = 0; i<cols; i++) {
        target[i] = i + 3.6;
        printf("%5.2f ", target[i]);
    }
    printf("\n");
    double score;
    double norm_score = -1;
    score = score_keystrokes(x, rows, cols, target, &norm_score);
    printf("%f\n", score);
}
