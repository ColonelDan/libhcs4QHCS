//#define DEBUG

//include QAT headers
#include "../include/libhcs/pcs_qat_offload.h"

void test()
{
	PRINT_DBG("test !\n");
}

static sampleThread gPollingThreadMultiInst;
static int gPollingCyMultiInst = 0;
struct pollingParam {
    CpaInstanceHandle* pCyInstHandle;
    Cpa16U numInst;
};
/*
 * This function polls a crypto instance.
 *
 */
static void sal_pollingMultiInst(void* argVoid)
{
    struct pollingParam* arg = (struct pollingParam*)argVoid;
    gPollingCyMultiInst = 1;
    while (gPollingCyMultiInst)
    {
        for (int i = 0; i < arg->numInst; i++)
        {
			icp_sal_CyPollInstance(arg->pCyInstHandle[i], 0);
        }
        OS_SLEEP(10);
    }
    free(arg);
    sampleThreadExit();
}
/*
 * This function checks the instance info. If the instance is
 * required to be polled then it starts a polling thread.
 */
void sampleCyStartPollingMultiInst(CpaInstanceHandle* pCyInstHandle, Cpa16U numInst)
{
    struct pollingParam* pArg = (struct pollingParam*)malloc(sizeof(struct pollingParam));
    pArg->numInst = numInst;
    pArg->pCyInstHandle = pCyInstHandle;

    /* Start thread to poll instance */
    sampleThreadCreate(&gPollingThreadMultiInst, sal_pollingMultiInst, pArg);

    //free(pArg);
}
/*
 * This function stops the polling of a crypto instance.
 */
void sampleCyStopPollingMultiInst(void)
{
    gPollingCyMultiInst = 0;
    OS_SLEEP(10);
}

/**
 *****************************************************************************
 * @ingroup fipsSampleCodeUtils
 *      doModExpWithInterval
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
CpaStatus doModExpWithInterval(const CpaFlatBuffer* restrict pBase,
    const CpaFlatBuffer* restrict pExponent,
    const CpaFlatBuffer* restrict pModulus,
    CpaFlatBuffer* pTarget,
    const CpaInstanceHandle instanceHandle)
{

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
        .exponent = {.dataLenInBytes = 0, .pData = NULL} };

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

    do
    {
        status = cpaCyLnModExp(instanceHandle,
            NULL, /*callback function*/
            NULL, /*callback tag*/
            &modExpOpData,
            pTarget);
        if ((CPA_STATUS_RETRY != status) && (CPA_STATUS_SUCCESS != status))
        {
            if (CPA_STATUS_SUCCESS !=
                cpaCyGetStatusText(instanceHandle, status, statusErrorString))
            {
                PRINT_ERR("Error retrieving status string.\n");
            }
            PRINT_ERR("doModExpWithInterval Fail -- %s\n", statusErrorString);
            status = CPA_STATUS_FAIL;
            goto finish;
        }
        if (CPA_STATUS_SUCCESS == status)
        {
            break;
        }
        maxCyRetries++;

        // interval
        OS_SLEEP(10);
		icp_sal_CyPollInstance(instanceHandle, 0);
    } while ((CPA_STATUS_RETRY == status) &&
        FIPS_MAX_CY_RETRIES != maxCyRetries);  //FIPS_MAX_CY_RETRIES (100)

/*Sets fail if maxCyRetries == FIPS_MAX_CY_RETRIES*/
    CHECK_MAX_RETRIES(maxCyRetries, status);

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
	sampleCyStartPollingMultiInst(CyInstHandle, *numInst_g);
	return stat;
}

//mpz_export
char* data_export(const mpz_t* mpz_data, size_t* got_count)
{
	void *ret;
	//			size_t got_count;
	int char_data_size = (*mpz_data)[0]._mp_size * sizeof(mp_limb_t);
	//std::cout << "char_data_size = " << char_data_size << std::endl;
	PRINT_DBG("char_data_size = %d\n", char_data_size);
	//			char char_data[char_data_size];
	//			char_data = 0x1111;
	//			std::cout<<"*************"<<std::endl;
	//char* char_data_ = new char[abs(char_data_size)];
	char* char_data_ = (char *)malloc(abs(char_data_size));
	memset(char_data_, '\0', abs(char_data_size));

	ret = mpz_export(char_data_, got_count, 1, 1, 1, 0, *mpz_data);
	//std::cout << "got_count = " << got_count << std::endl;
	PRINT_DBG("got_count = %d\n", *got_count);
	return char_data_;
	//			char_data = char_data_;
}
//	void data_export(char* char_data_, const mpz_t& mpz_data)
//	{
//			void *ret;
//			size_t got_count;
//			int char_data_size = mpz_data[0]._mp_size * sizeof(mp_limb_t);
//			std::cout<<"char_data_size = "<<char_data_size<<std::endl;
////			char char_data[char_data_size];
////			char_data = new char[char_data_size];
//			char char_data[char_data_size];
//			memset(char_data, '\0', char_data_size);
//
//			ret = mpz_export(char_data, &got_count, 1, 1, 1, 0, mpz_data);
//			std::cout<<"got_count = "<<got_count<<std::endl;
//	}

	//mpz_import
void data_import(char* char_data, mpz_t* mpz_data, size_t count)
{
	//		mpz_t mpz_data;
	mpz_init(*mpz_data);
	mpz_import(*mpz_data, count, 1, 1, 1, 0, char_data);
}

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

CpaFlatBuffer* ModExp(char* a, size_t a_size,
	char* b, size_t b_size,
	char* m, size_t m_size,
	CpaInstanceHandle *pCyInstHandle)
{
	CpaStatus status = CPA_STATUS_SUCCESS;


	CpaFlatBuffer* aCpaFlatBuffer = NULL;
	CpaFlatBuffer* bCpaFlatBuffer = NULL;
	CpaFlatBuffer* mCpaFlatBuffer = NULL;
	CpaFlatBuffer* resultCpaFlatBuffer = NULL;
	aCpaFlatBuffer = WarpData(a, a_size, 0);
	bCpaFlatBuffer = WarpData(b, b_size, 0);
	mCpaFlatBuffer = WarpData(m, m_size, 0);
	resultCpaFlatBuffer = WarpData(NULL, m_size, 1);

	status = doModExpWithInterval(
		aCpaFlatBuffer,
		bCpaFlatBuffer,
		mCpaFlatBuffer,
		resultCpaFlatBuffer,
		*pCyInstHandle);
	//std::cout << "end of  ModExp" << std::endl;

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

CpaFlatBuffer* ModInv(char* a, size_t a_size,
	char* m, size_t m_size,
	CpaInstanceHandle *pCyInstHandle)
{
	CpaStatus status = CPA_STATUS_SUCCESS;


	CpaFlatBuffer* aCpaFlatBuffer = NULL;
	CpaFlatBuffer* mCpaFlatBuffer = NULL;
	CpaFlatBuffer* resultCpaFlatBuffer = NULL;
	aCpaFlatBuffer = WarpData(a, a_size, 0);
	mCpaFlatBuffer = WarpData(m, m_size, 0);
	resultCpaFlatBuffer = WarpData(NULL, m_size, 1);

	status = doModInv(
		aCpaFlatBuffer,
		mCpaFlatBuffer,
		resultCpaFlatBuffer,
		*pCyInstHandle);
	//std::cout << "end of  ModInv" << std::endl;
	PRINT_DBG("end of ModInv !\n");
	return resultCpaFlatBuffer;


}


void PowModN (mpz_t *output, const mpz_t *input, const mpz_t *power, const mpz_t *n, CpaInstanceHandle *pCyInstHandle) {

 	// mpz_powm(output.data, input.data, power.data, n.data);

 	// struct timeval t_val;
 	// gettimeofday(&t_val, NULL);
 	// PRINT_DBG("start, now, sec=%ld m_sec=%d \n", t_val.tv_sec, t_val.tv_usec);
 	// long sec = t_val.tv_sec;
 	// time_t t_sec = (time_t)sec;
 	// PRINT_DBG("date:%s", ctime(&t_sec));		

 	//export
 	char *power_char_data, *input_char_data, *n_char_data;
 	size_t power_count, input_count, n_count;
 	power_char_data = data_export(power, &power_count);
 	input_char_data = data_export(input, &input_count);
 	n_char_data = data_export(n, &n_count);

 	CpaFlatBuffer *result_flat_data;
 	CpaFlatBuffer *modInv_flat_data;
 	mpz_t result_mpz_data;
 	if((*power)[0]._mp_size > 0)
 	{
 		//struct timeval t_val;
 		//gettimeofday(&t_val, NULL);
 		//PRINT_DBG("start, now, sec=%ld m_sec=%d \n", t_val.tv_sec, t_val.tv_usec);
 		//long sec = t_val.tv_sec;
 		//time_t t_sec = (time_t)sec;
 		//PRINT_DBG("date:%s", ctime(&t_sec));	

 		result_flat_data = ModExp(	input_char_data, input_count,
 			power_char_data, power_count,
 			n_char_data, n_count,
			pCyInstHandle);

 		//struct timeval t_val_end;
 		//gettimeofday(&t_val_end, NULL);
 		//struct timeval t_result;
 		//timersub(&t_val_end, &t_val, &t_result);
 		//double consume = t_result.tv_sec + (1.0 * t_result.tv_usec)/1000000;
 		//PRINT_DBG("%d. -------------- end.elapsed time= %fs \n\n", count, consume);
 		//count++;

 		// mpz_t result_mpz_data;
 		data_import((char*)(result_flat_data->pData), result_mpz_data, 	(size_t)(result_flat_data->dataLenInBytes));

 		mpz_set(output, result_mpz_data);

        //free mem
		PHYS_CONTIG_FREE(result_flat_data->pData);
		OS_FREE(result_flat_data);
 	}
 	else if((*power)[0]._mp_size < 0)
 	{
 		//struct timeval t_val;
 		//gettimeofday(&t_val, NULL);
 		//PRINT_DBG("start, now, sec=%ld m_sec=%d \n", t_val.tv_sec, t_val.tv_usec);
 		//long sec = t_val.tv_sec;
 		//time_t t_sec = (time_t)sec;
 		//PRINT_DBG("date:%s", ctime(&t_sec));


 		modInv_flat_data = ModInv(	input_char_data, input_count,
 									n_char_data, n_count,
									pCyInstHandle);

 		result_flat_data = ModExp(	(char*)(modInv_flat_data->pData), modInv_flat_data->dataLenInBytes,
 			power_char_data, power_count,
 			n_char_data, n_count,
			pCyInstHandle);

 		//struct timeval t_val_end;
 		//gettimeofday(&t_val_end, NULL);
 		//struct timeval t_result;
 		//timersub(&t_val_end, &t_val, &t_result);
 		//double consume = t_result.tv_sec + (1.0 * t_result.tv_usec)/1000000;
 		//PRINT_DBG("%d. -------------- end.elapsed time (negative need modInv & modExp)= %fs \n\n", count, consume);
 		//count++;

 		data_import((char*)(result_flat_data->pData), result_mpz_data, 	(size_t)(result_flat_data->dataLenInBytes));

 		mpz_set(output, result_mpz_data);
 	}
 	else
 	{
 		mpz_set_ui(output, 1);
 	}

    //free mem
    free(power_char_data);
    free(input_char_data);
    free(n_char_data);

 	//import
 	// mpz_t power_mpz_data, result_mpz_data;
 	// data_import(power_char_data, power_mpz_data, power_count);
 	// data_import((char*)(result_flat_data->pData), result_mpz_data, 	size_t(result_flat_data->dataLenInBytes));

 	// // output.data = &result_mpz_data;
 	// mpz_set(output.data, result_mpz_data);

 	//std::cout<<"end of BigIntegerGmp::PowModN ."<<std::endl;
	PRINT_DBG("end of PowModN !\n");

 	// struct timeval t_val_end;
 	// gettimeofday(&t_val_end, NULL);
 	// struct timeval t_result;
 	// timersub(&t_val_end, &t_val, &t_result);
 	// double consume = t_result.tv_sec + (1.0 * t_result.tv_usec)/1000000;
 	// PRINT_DBG("%d. -------------- end.elapsed time= %fs \n\n", count, consume);
 	// count++;

 	//compare
// //		int cmp_ret = mpz_cmp(power_mpz_data, power.data);
// 		int cmp_ret = mpz_cmp(result_mpz_data, output.data);
// 		std::cout<<"cmp_ret = "<<cmp_ret<<std::endl;



//		void *ret;
//		size_t got_count;
//		int char_data_size = power.data[0]._mp_size * sizeof(mp_limb_t);
//		std::cout<<"char_data_size = "<<char_data_size<<std::endl;
//		char char_data[char_data_size];
//		memset(char_data, '\0', char_data_size);
//
//		ret = mpz_export(char_data, &got_count, 1, 1, 1, 0, power.data);
//		std::cout<<"got_count = "<<got_count<<std::endl;
//
////		SeComLib::Core::BigInteger  mpz_data;
//		mpz_t mpz_data;
//		mpz_init(mpz_data);
//		mpz_import(mpz_data, got_count, 1, 1, 1, 0, char_data);
//		int cmp_ret = mpz_cmp(mpz_data, power.data);
//		std::cout<<"cmp_ret = "<<cmp_ret<<std::endl;

}