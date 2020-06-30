#include "pcs_matrix.h"

#include <openssl/async.h>
#include <openssl/crypto.h>
#include <unistd.h>

#include <sys/time.h>

//--------------------------------------------------------------------- simple matrix

simple_matrix *simple_matrix_init(int m,int n){
    simple_matrix *mat=(simple_matrix *)malloc(sizeof(simple_matrix));
    mat->simple_array=(mpz_t *)malloc(m*n*sizeof(mpz_t));
    mat->m=m;
    mat->n=n;
    for(int i=0;i<m*n;i++){
        mpz_init(mat->simple_array[i]);
    }
    return mat;
}

void simple_matrix_free(simple_matrix *mat){
    free(mat->simple_array);
    free(mat);
}
void simple_mat_set_value(simple_matrix *mat,mpz_t val,int i,int j){
    int index=i*(mat->n)+j;
    mpz_set(mat->simple_array[index],val);
}

void simple_mat_get_value(simple_matrix *mat,mpz_t ret,int i,int j){
    int index=i*(mat->n)+j;
    mpz_set(ret,mat->simple_array[index]);
}

//------------------------------------------------------------------------ cipher matrix

PCS_matrix *PCS_init_matrix(int m,int n){
    PCS_matrix *mat=(PCS_matrix *)malloc(sizeof(PCS_matrix));
    mat->PCS_array=(mpz_t *)malloc(m*n*sizeof(mpz_t));
    mat->m=m;
    mat->n=n;
    for(int i=0;i<m*n;i++){
        mpz_init(mat->PCS_array[i]);
    }
    return mat;
}

void PCS_free_matrix(PCS_matrix *mat){
    free(mat->PCS_array);
    free(mat);
}
void PCS_mat_set_value(PCS_matrix *mat,mpz_t val,int i,int j){
    int index=i*(mat->n)+j;
    mpz_set(mat->PCS_array[index],val);
}

void PCS_mat_get_value(PCS_matrix *mat,mpz_t ret,int i,int j){
    int index=i*(mat->n)+j;
    mpz_set(ret,mat->PCS_array[index]);
}

//-------------------------------------------------------------------------------- matrix encrypt

struct elem_enc_t {
	simple_matrix* src_matrix;
	PCS_matrix* des_matrix;
	int i;
	int j;
	CpaInstanceHandle *pCyInstHandle;
	pcs_public_key *pk;
	hcs_random *hr;
	int *pTaskNum;
    struct timeval* pT_sum; // 加密用时
};

//int taskNum = 0;

//矩阵中每个元素（数）的加密过程
int element_encrypt(void *argVoid)
{
	struct elem_enc_t *arg = (struct elem_enc_t *)argVoid;
	(*(arg->pTaskNum))++;

	//timeval start
	struct timeval t_val;
	gettimeofday(&t_val, NULL);

	mpz_t tmp1;
	mpz_init(tmp1);
	simple_mat_get_value(arg->src_matrix, tmp1, arg->i, arg->j);
	pcs_encrypt(arg->pk, arg->hr, tmp1, tmp1, arg->pCyInstHandle);  //调用libhcs API
	PCS_mat_set_value(arg->des_matrix, tmp1, arg->i, arg->j);

	//timeval end
	struct timeval t_val_end;
	gettimeofday(&t_val_end, NULL);
	struct timeval t_result;
	timersub(&t_val_end, &t_val, &t_result);
	timeradd(arg->pT_sum, &t_result, arg->pT_sum);  //延时累加

	//free(arg);
	(*(arg->pTaskNum))--;
	//printf("async_job completed with taskNum = %d !\n", *(arg->ptaskNum));
	return 0;
}

// 引入QAT API
extern "C" {
	CpaStatus icp_sal_CyPollInstance(CpaInstanceHandle instanceHandle,
		Cpa32U response_quota);
}

// 矩阵加密
PCS_matrix *matrix_encrypt(pcs_public_key *pk,simple_matrix *mat, CpaInstanceHandle* pCyInstHandle, int pollThreshold){
	// 避免触及请求队列长度的极限
	if (pollThreshold == 1024)
		pollThreshold = 1022;

    PCS_matrix *mat_ret=PCS_init_matrix(mat->m,mat->n);
    hcs_random *hr = hcs_init_random();

	// elem_enc_t arg
	int taskNum = 0;    //已提交而未回收的请求数量
    struct timeval t_sum;   //延时累加值

    // 协程相关
    int ret;
	ASYNC_JOB* job = NULL;  // 协程句柄
	ASYNC_WAIT_CTX* ctx = NULL;
	ctx = ASYNC_WAIT_CTX_new();
	if (ctx == NULL) {
		printf("Failed to create ASYNC_WAIT_CTX\n");
		abort();
	}

    // 对输入数据进行10000次重复加密
    for (int k = 0; k < 10000; k++) {
		for (int i = 0; i < mat->m; i++) {
			for (int j = 0; j < mat->n; j++) {
				struct elem_enc_t* pArg = (struct elem_enc_t*)malloc(sizeof(struct elem_enc_t));
				pArg->src_matrix = mat;
				pArg->des_matrix = mat_ret;
				pArg->i = i;
				pArg->j = j;
				pArg->pCyInstHandle = pCyInstHandle;
				pArg->pk = pk;
				pArg->hr = hr;
				pArg->pTaskNum = &taskNum;
				pArg->pT_sum = &t_sum;

				job = NULL;
				if (taskNum >= 1) //100
				{
					icp_sal_CyPollInstance(*pCyInstHandle, 0);  //taskNum大于一个较小的阈值时进行一次轮询
					while (taskNum > pollThreshold) //taskNum大于阈值的极限时，持续轮询
					{
						if (CPA_STATUS_RETRY == icp_sal_CyPollInstance(*pCyInstHandle, 0));
						//sleep(1);
					}
				}

				//发起一个协程提交一个加密任务
				switch (ASYNC_start_job(&job, ctx, &ret, element_encrypt, pArg, sizeof(struct elem_enc_t)))
				{
				case ASYNC_ERR:
				case ASYNC_NO_JOBS:
					printf("An error occurred\n");
					goto end;
				case ASYNC_PAUSE:
					//printf("Job was paused\n");
					break;
				case ASYNC_FINISH:
					printf("Job finished with return value %d\n", ret);
					break;
				}
			}
		}
    }
	
	CpaStatus status;
	while(taskNum != 0) //在最后需要将所有提交的任务回收
		status = icp_sal_CyPollInstance(*pCyInstHandle, 0);

	//get latency
	double consume;
	consume = t_sum.tv_sec + (1.0 * t_sum.tv_usec) / 1000000;
	printf("latency sum = %fs \n", consume);
	printf("latency = %fs \n", consume / 10000);

end:
	ASYNC_WAIT_CTX_free(ctx);
	printf("Finishing\n");
    
    hcs_free_random(hr);
    return mat_ret;
}