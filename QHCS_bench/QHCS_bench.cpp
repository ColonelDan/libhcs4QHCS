#include <gmp.h>    // gmp is included implicitly
#include <libhcs.h> // master header includes everything
#include <stdlib.h>
#include <string.h>
#include "pcs_matrix.h"
#include <sys/time.h>

// instance
CpaInstanceHandle pCyInstHandle[8] = { 0 };
unsigned short numInst;

// pk & vk
pcs_public_key* pk;
pcs_private_key* vk;
hcs_random* hr;

// thread
pthread_t* threads;
struct threadArg {
	int thread_index;
	int bitKey;
	int pollThreshold;
};

// 线程函数
void* singleThreadFunc(void* arg)
{
	struct threadArg* Arg = (struct threadArg*)arg;

	// 输入输出数据都为一维，即一个数据重复进行运算
	int m = 1;
	int n = 1;
	// 输入数据
	simple_matrix* mul_mat_int = simple_matrix_init(n, n);
	// 输出数据
	//PCS_matrix* mul_mat_enc = PCS_init_matrix(n, n);
	PCS_matrix* mul_mat_enc;

	// 得到待处理的输入数据
	mpz_t temp;
	mpz_init(temp);
	mpz_set_si(temp, 1);
	mpz_mul_2exp(temp, temp, Arg->bitKey - 1);	//左移
	simple_mat_set_value(mul_mat_int, temp, 0, 0);

	// 进行加密
	mul_mat_enc = matrix_encrypt(pk, mul_mat_int, pCyInstHandle + Arg->thread_index % numInst, Arg->pollThreshold);

	free(arg);
	simple_matrix_free(mul_mat_int);
	PCS_free_matrix(mul_mat_enc);
}

// 进行一组测试
int Test(int nThread, int bitKey, int pollThreshold) {
	CpaStatus rt = QATSetting(&numInst, pCyInstHandle);	//libhcs中提供的API
	//int numThread = 3;

    // initialize data structures
    pk = pcs_init_public_key();
    vk = pcs_init_private_key();
    hr = hcs_init_random();

    // Generate a key pair with modulus of size "bitKey" bits
    pcs_generate_key_pair(pk, vk, hr, bitKey);

	// 配置线程空间
	threads = (pthread_t*)malloc(sizeof(pthread_t*) * nThread);
	// 线程索引
	int thread_index = 0;

	//timeval start
	struct timeval t_val;
	gettimeofday(&t_val, NULL);
	//printf("init start, now, sec=%ld m_sec=%d \n", t_val.tv_sec, t_val.tv_usec);
	long sec = t_val.tv_sec;
	time_t t_sec = (time_t)sec;

	// 每个线程都进行任务提交
	for (thread_index = 0; thread_index < nThread; thread_index++)
	{
		//int* arg = (int*)malloc(sizeof(int));
		//*arg = thread_index;
		struct threadArg* arg = (struct threadArg*)malloc(sizeof(struct threadArg));
		arg->bitKey = bitKey;
		arg->pollThreshold = pollThreshold;
		arg->thread_index = thread_index;

		printf("Create thread %d\n", thread_index);
		pthread_create(&threads[thread_index], NULL, singleThreadFunc, arg);
	}

	// 线程运行结束
	for (thread_index = 0; thread_index < nThread; thread_index++)
	{
		pthread_join(threads[thread_index], NULL);
	}

	//timeval end
	struct timeval t_val_end;
	gettimeofday(&t_val_end, NULL);
	struct timeval t_result;
	timersub(&t_val_end, &t_val, &t_result);
	double consume = t_result.tv_sec + (1.0 * t_result.tv_usec) / 1000000;
	printf("-------------- elapsed time= %fs \n", consume);
	printf("-------------- Throughput = %f\n", 10000.0 * nThread / consume);

	free(threads);
    pcs_free_public_key(pk);
    pcs_free_private_key(vk);
    hcs_free_random(hr);
}

int main()
{
	//进行不同参数下的多组测试
	for (int nThread = 3; nThread <= 3; nThread *= 3)
	//for (int nThread = 6; nThread <= 6; nThread *= 3)	//线程数
	{
		for (int bitKey = 1024; bitKey <= 2048; bitKey *= 2)	//密钥长度
		{
			for (int pollThreshold = 1024; pollThreshold <= 1024; pollThreshold *= 2)	//最大轮询阈值
			{
				printf("******************nThread = %d, bitKey = %d, pollThreshold = %d********************\n", nThread, bitKey, pollThreshold);
				Test(nThread, bitKey, pollThreshold);
			}
		}
	}
	return 0;
}