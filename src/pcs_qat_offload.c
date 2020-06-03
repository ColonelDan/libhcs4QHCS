//include QAT headers
//#define DEBUG
#include "../include/libhcs/pcs_qat_offload.h"

#include <openssl/async.h>
#include <openssl/crypto.h>

//异步API需要回调函数
static void asymCallback(void *pCallbackTag,
	CpaStatus status,
	void *pOpData,
	CpaFlatBuffer *pOut)
{
	//PRINT_DBG("CallBack function\n");

	if (CPA_STATUS_SUCCESS != status)
	{
		PRINT_ERR("operation not a success, status = %d\n", status);
	}

	//PRINT_DBG("asymCallback: status = %d\n", status);

	ASYNC_JOB *job = (ASYNC_JOB *)pCallbackTag;
	int ret;

	//根据协程句柄重入协程
	ASYNC_start_job(&job, NULL, &ret, NULL, NULL, NULL);
}
/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      doModExp
 *
 * @description
 *      Do a Modular Exponentiation operaton
 *      target = (base ^ exponent) mod (modulus);
 *
 * @param[in]  pBase             base value
 * @param[in]  pExponent         exponent value, if this value is NULL, an
 *                               exponent of 1 is used.
 * @param[in]  pModulus          modulus value
 * @param[in]  instanceHandle    QA instance handle
 *
 * @param[out] pTarget           result value
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
CpaStatus doModExpAsync(const CpaFlatBuffer *restrict pBase,
	const CpaFlatBuffer *restrict pExponent,
	const CpaFlatBuffer *restrict pModulus,
	CpaFlatBuffer *pTarget,
	const CpaInstanceHandle instanceHandle)
{
	PRINT_DBG("now is doModExpAsync !\n");
	CpaStatus status = CPA_STATUS_SUCCESS;
	Cpa32U maxCyRetries = 0;
	Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
		0,
	};
	CpaCyLnModExpOpData modExpOpData = {
		.modulus = {.dataLenInBytes = pModulus->dataLenInBytes,
					.pData = pModulus->pData},
		.base = {.dataLenInBytes = pBase->dataLenInBytes,
				 .pData = pBase->pData},
		.exponent = {.dataLenInBytes = 0,.pData = NULL} };

	/*if exponent is NULL, set value to 1*/
	if (NULL == pExponent)
	{
		modExpOpData.exponent.pData = osZalloc(1, instanceHandle);
		if (NULL == modExpOpData.exponent.pData)
		{
			PRINT_ERR("internal exponent alloc fail \n");
			status = CPA_STATUS_FAIL;
			goto finish;
		}
		*modExpOpData.exponent.pData = 1;
		modExpOpData.exponent.dataLenInBytes = 1;
	}
	else
	{
		modExpOpData.exponent.pData = pExponent->pData;
		modExpOpData.exponent.dataLenInBytes = pExponent->dataLenInBytes;
	}

	//得到当前协程句柄
	ASYNC_JOB *currjob = ASYNC_get_current_job();

	do
	{
		status = cpaCyLnModExp(instanceHandle,
			asymCallback, /*callback function*/
			currjob, /*callback tag*/	//回调函数根据协程句柄可以重入协程
			&modExpOpData,
			pTarget);
		//if (status == CPA_STATUS_RETRY)
		//{
		//	while (icp_sal_CyPollInstance(instanceHandle, 0) != CPA_STATUS_SUCCESS)
		//		;
		//}

		if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
		{
			if (CPA_STATUS_SUCCESS !=
				cpaCyGetStatusText(instanceHandle, status, statusErrorString))
			{
				PRINT_ERR("Error retrieving status string.\n");
			}
			PRINT_ERR("doModExp Fail -- %s\n", statusErrorString);
			status = CPA_STATUS_FAIL;
			goto finish;
		}
		if (CPA_STATUS_SUCCESS == status)
		{
			break;
		}
		maxCyRetries++;
	} while ((CPA_STATUS_RETRY == status) &&
		1000000000 != maxCyRetries);	//FIPS_MAX_CY_RETRIES != maxCyRetries);

	/*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
	CHECK_MAX_RETRIES(maxCyRetries, status);

	//提交成功，暂停协程
	ASYNC_pause_job();

finish:
	if (NULL == pExponent)
	{
		osFree(&modExpOpData.exponent.pData);
	}
	if (CPA_STATUS_SUCCESS != status)
	{
		return CPA_STATUS_FAIL;
	}
	return CPA_STATUS_SUCCESS;
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      doModInv
 *
 * @description
 *      Get the inverse modulus of a number:
 *      target = (base ^ -1) mod (modulus);
 *
 * @param[in]  pBase             base value
 * @param[in]  pModulus          modulus value
 * @param[out] pTarget           Result is stored here
 * @param[in]  instanceHandle    QA instance handle
 *
 * @retval CPA_STATUS_SUCCESS
 *         CPA_STATUS_FAIL
 *
 * @pre
 *     none
 * @post
 *     none
 *****************************************************************************/
//NOTE:doModInvAsync部分没有经过测试，开发不完全！可根据doModExpAsync进行完善。
CpaStatus doModInvAsync(const CpaFlatBuffer *restrict pBase,
	const CpaFlatBuffer *restrict pModulus,
	CpaFlatBuffer *pTarget,
	const CpaInstanceHandle instanceHandle)
{

	CpaStatus status = CPA_STATUS_SUCCESS;
	Cpa32U maxCyRetries = 0;
	Cpa8S statusErrorString[CPA_STATUS_MAX_STR_LENGTH_IN_BYTES] = {
		0,
	};
	CpaCyLnModInvOpData modInvOpData = {
		.A = {.dataLenInBytes = pBase->dataLenInBytes,.pData = pBase->pData},
		.B = {.dataLenInBytes = pModulus->dataLenInBytes,
			  .pData = pModulus->pData} };

	ASYNC_JOB *currjob = ASYNC_get_current_job();

	do
	{
		status = cpaCyLnModInv(instanceHandle,
			asymCallback, /*callback function*/
			currjob, /*callback tag*/
			&modInvOpData,
			pTarget);
		if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
		{
			if (CPA_STATUS_SUCCESS !=
				cpaCyGetStatusText(instanceHandle, status, statusErrorString))
			{
				PRINT_ERR("Error retrieving status string.\n");
			}
			PRINT_ERR("Mod Inv Fail -- %s\n", statusErrorString);
			status = CPA_STATUS_FAIL;
			break;
		}
		if (CPA_STATUS_SUCCESS == status)
		{
			break;
		}
		maxCyRetries++;
	} while ((CPA_STATUS_RETRY == status) &&
		FIPS_MAX_CY_RETRIES != maxCyRetries);

	/*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
	CHECK_MAX_RETRIES(maxCyRetries, status);
	ASYNC_pause_job();

	if (CPA_STATUS_SUCCESS != status)
	{
		return CPA_STATUS_FAIL;
	}
	return CPA_STATUS_SUCCESS;
}

void test()
{
	PRINT_DBG("test !\n");
}

//获取所有instance句柄放在inst_g，instance数量为numInst_g
CpaStatus getCryptoInstance(Cpa16U* numInst_g, CpaInstanceHandle* inst_g)
{

	CpaStatus status = CPA_STATUS_FAIL;
	Cpa32U i = 0;
	Cpa32U coreAffinity = 0;
	CpaInstanceInfo2 info = { 0 };

	/*get the number of crypto instances*/
	status = cpaCyGetNumInstances(numInst_g);
	// numInst_g--;
	if (CPA_STATUS_SUCCESS != status)
	{
		PRINT_ERR("cpaCyGetNumInstances failed with status: %d\n", status);
		return status;
	}
	PRINT_DBG("numInst_g = %hd\n", *numInst_g);
	if (*numInst_g > 0)
	{
		/*allocate memory to store the instance handles*/
		//*inst_g = qaeMemAlloc(sizeof(CpaInstanceHandle) * (*numInst_g));

		//inst_g = malloc(sizeof(CpaInstanceHandle) * (*numInst_g));
		//CpaInstanceHandle* test = NULL;
		////test = malloc(sizeof(CpaInstanceHandle) * (*numInst_g));
		//test = (CpaInstanceHandle*)malloc(sizeof(CpaInstanceHandle) * (*numInst_g));
		//inst_g = test;


		if (inst_g == NULL)
		{
			PRINT_ERR("Failed to allocate memory for instances\n");
			return CPA_STATUS_FAIL;
		}
		/*get the instances handles and place in allocated memory*/
		status = cpaCyGetInstances(*numInst_g, inst_g);
		if (CPA_STATUS_SUCCESS != status)
		{
			PRINT_ERR("cpaCyGetInstances failed with status: %d\n", status);
			return status;
		}

		/*start all instances*/
		for (int i = 0; i < *numInst_g; i++)
		{
			if (status = cpaCyStartInstance(*(inst_g + i)) == CPA_STATUS_FAIL)
				return CPA_STATUS_FAIL;
			if (status = cpaCySetAddressTranslation(*(inst_g + i), sampleVirtToPhys) == CPA_STATUS_FAIL)
				return CPA_STATUS_FAIL;
		}

	}
	else
	{
		PRINT("There are no crypto instances\n");
		return CPA_STATUS_FAIL;
	}
	// numInst_g--;
	return status;
}

//启用QAT
CpaStatus QATSetting(Cpa16U* numInst_g, CpaInstanceHandle* CyInstHandle)
{
	CpaStatus stat = CPA_STATUS_SUCCESS;

	stat = qaeMemInit();
	if (CPA_STATUS_SUCCESS != stat)
	{
		PRINT_ERR("Failed to initialise memory driver\n");
		return (int)stat;
	}

	stat = icp_sal_userStartMultiProcess("SSL", CPA_FALSE);
	if (CPA_STATUS_SUCCESS != stat)
	{
		PRINT_ERR("Failed to start user process SSL\n");
		qaeMemDestroy();
		return (int)stat;
	}

	//stat = fipsSampleGetQaInstance(CyInstHandle);
	//sampleCyStartPolling(*CyInstHandle);
	stat = getCryptoInstance(numInst_g, CyInstHandle);
	return stat;
}

//mpz_export
char* data_export(const mpz_t* mpz_data, size_t* got_count)
{
	void *ret;
	int char_data_size = (*mpz_data)[0]._mp_size * sizeof(mp_limb_t);
	PRINT_DBG("char_data_size = %d\n", char_data_size);
	char* char_data_ = (char *)malloc(abs(char_data_size));
	memset(char_data_, '\0', abs(char_data_size));

	ret = mpz_export(char_data_, got_count, 1, 1, 1, 0, *mpz_data);
	PRINT_DBG("got_count = %d\n", *got_count);
	return char_data_;
}

//mpz_import
void data_import(char* char_data, mpz_t* mpz_data, size_t count)
{
	mpz_init(*mpz_data);
	mpz_import(*mpz_data, count, 1, 1, 1, 0, char_data);
}

//根据二进制a及二进制长度a_size封装得到QAT接口格式aCpaFlatBuffer
CpaFlatBuffer* WarpData(char* a, size_t a_size, int empty)
{
	CpaStatus status = CPA_STATUS_SUCCESS;
	CpaFlatBuffer* aCpaFlatBuffer = NULL;
	status = OS_MALLOC(&aCpaFlatBuffer, sizeof(CpaFlatBuffer));
	if (status == CPA_STATUS_SUCCESS)
	{
		memset(aCpaFlatBuffer, 0, sizeof(CpaFlatBuffer));
		aCpaFlatBuffer->dataLenInBytes = a_size;
		status = PHYS_CONTIG_ALLOC(&aCpaFlatBuffer->pData, a_size);

		if ((NULL != aCpaFlatBuffer->pData) && (!empty))
		{
			memcpy(aCpaFlatBuffer->pData, a, a_size);
		}
	}
	return aCpaFlatBuffer;
}

//模幂（模幂中间层函数）
CpaFlatBuffer* ModExp(char* a, size_t a_size,
	char* b, size_t b_size,
	char* m, size_t m_size,
	CpaInstanceHandle *pCyInstHandle)
{
	CpaStatus status = CPA_STATUS_SUCCESS;

	//封装得到CpaFlatBuffer格式数据
	CpaFlatBuffer* aCpaFlatBuffer = NULL;
	CpaFlatBuffer* bCpaFlatBuffer = NULL;
	CpaFlatBuffer* mCpaFlatBuffer = NULL;
	CpaFlatBuffer* resultCpaFlatBuffer = NULL;
	aCpaFlatBuffer = WarpData(a, a_size, 0);
	bCpaFlatBuffer = WarpData(b, b_size, 0);
	mCpaFlatBuffer = WarpData(m, m_size, 0);
	resultCpaFlatBuffer = WarpData(NULL, m_size, 1);

	//模幂底层函数
	status = doModExpAsync(
		aCpaFlatBuffer,
		bCpaFlatBuffer,
		mCpaFlatBuffer,
		resultCpaFlatBuffer,
		*pCyInstHandle);

	//free mem
	PHYS_CONTIG_FREE(aCpaFlatBuffer->pData);
	PHYS_CONTIG_FREE(bCpaFlatBuffer->pData);
	PHYS_CONTIG_FREE(mCpaFlatBuffer->pData);
	//PHYS_CONTIG_FREE(resultCpaFlatBuffer->pData);
	OS_FREE(aCpaFlatBuffer);
	OS_FREE(bCpaFlatBuffer);
	OS_FREE(mCpaFlatBuffer);
	//OS_FREE(resultCpaFlatBuffer);

	PRINT_DBG("end of ModExp!\n");
	return resultCpaFlatBuffer;


}

//模反（模幂中间层函数）
CpaFlatBuffer* ModInv(char* a, size_t a_size,
	char* m, size_t m_size,
	CpaInstanceHandle *pCyInstHandle)
{
	CpaStatus status = CPA_STATUS_SUCCESS;

	//封装得到CpaFlatBuffer格式数据
	CpaFlatBuffer* aCpaFlatBuffer = NULL;
	CpaFlatBuffer* mCpaFlatBuffer = NULL;
	CpaFlatBuffer* resultCpaFlatBuffer = NULL;
	aCpaFlatBuffer = WarpData(a, a_size, 0);
	mCpaFlatBuffer = WarpData(m, m_size, 0);
	resultCpaFlatBuffer = WarpData(NULL, m_size, 1);

	//模反底层函数
	status = doModInvAsync(
		aCpaFlatBuffer,
		mCpaFlatBuffer,
		resultCpaFlatBuffer,
		*pCyInstHandle);
	PRINT_DBG("end of ModInv !\n");
	return resultCpaFlatBuffer;


}

//模幂顶层函数
void PowModN (mpz_t *output, const mpz_t *input, const mpz_t *power, const mpz_t *n, CpaInstanceHandle *pCyInstHandle) {
 	//export
 	char *power_char_data, *input_char_data, *n_char_data;	//二进制数据
 	size_t power_count, input_count, n_count;	//二进制长度
 	power_char_data = data_export(power, &power_count);	//参数转为二进制数据，适应QAT接口
 	input_char_data = data_export(input, &input_count);
 	n_char_data = data_export(n, &n_count);

 	CpaFlatBuffer *result_flat_data;	//模幂结果
 	CpaFlatBuffer *modInv_flat_data;	//模反结果（指数为负数时的中间结果）
 	mpz_t result_mpz_data;	//模幂结果
 	if((*power)[0]._mp_size > 0)	//指数为正
 	{
		//模幂
 		result_flat_data = ModExp(	input_char_data, input_count,
 			power_char_data, power_count,
 			n_char_data, n_count,
			pCyInstHandle);

		//QAT格式转为mpz_t
 		data_import((char*)(result_flat_data->pData), result_mpz_data, 	(size_t)(result_flat_data->dataLenInBytes));

 		mpz_set(output, result_mpz_data);

		//free mem
		PHYS_CONTIG_FREE(result_flat_data->pData);
		OS_FREE(result_flat_data);
 	}
 	else if((*power)[0]._mp_size < 0)	//指数为负，需要预处理，见“https://zh.wikipedia.org/wiki/%E6%A8%A1%E5%B9%82”
 	{
		//对底数取模反
		//实现用QAT接口 or GMP接口 ?
		//Note:模反对象是底数，只与密钥相关，应该放在预处理中，只需要进行一次
 		modInv_flat_data = ModInv(	input_char_data, input_count,
 									n_char_data, n_count,
									pCyInstHandle);

		//模幂
 		result_flat_data = ModExp(	(char*)(modInv_flat_data->pData), modInv_flat_data->dataLenInBytes,
 			power_char_data, power_count,
 			n_char_data, n_count,
			pCyInstHandle);

		//QAT格式转为mpz_t
 		data_import((char*)(result_flat_data->pData), result_mpz_data, 	(size_t)(result_flat_data->dataLenInBytes));

 		mpz_set(output, result_mpz_data);
 	}
 	else   //指数为0
 	{
 		mpz_set_ui(output, 1);
 	}

	//free mem
	free(power_char_data);
	free(input_char_data);
	free(n_char_data);

	PRINT_DBG("end of PowModN !\n");
}