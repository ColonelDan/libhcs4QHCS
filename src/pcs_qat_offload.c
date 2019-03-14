//include QAT headers
#include "../include/libhcs/pcs_qat_offload.h"

void test()
{
	printf("test !\n");
}

CpaStatus QATSetting(CpaInstanceHandle* CyInstHandle)
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

	// return fipsSampleGetQaInstance(pCyInstHandle);
	stat = fipsSampleGetQaInstance(CyInstHandle);
	sampleCyStartPolling(*CyInstHandle);
	return stat;
}

//mpz_export
char* data_export(const mpz_t* mpz_data, size_t* got_count)
{
	void *ret;
	//			size_t got_count;
	int char_data_size = (*mpz_data)[0]._mp_size * sizeof(mp_limb_t);
	//std::cout << "char_data_size = " << char_data_size << std::endl;
	printf("char_data_size = %d\n", char_data_size);
	//			char char_data[char_data_size];
	//			char_data = 0x1111;
	//			std::cout<<"*************"<<std::endl;
	//char* char_data_ = new char[abs(char_data_size)];
	char* char_data_ = (char *)malloc(abs(char_data_size));
	memset(char_data_, '\0', abs(char_data_size));

	ret = mpz_export(char_data_, got_count, 1, 1, 1, 0, *mpz_data);
	//std::cout << "got_count = " << got_count << std::endl;
	printf("got_count = %d\n", *got_count);
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

	status = doModExp(
		aCpaFlatBuffer,
		bCpaFlatBuffer,
		mCpaFlatBuffer,
		resultCpaFlatBuffer,
		*pCyInstHandle);
	//std::cout << "end of  ModExp" << std::endl;
	printf("end of ModExp!\n");
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
	printf("end of ModInv !\n");
	return resultCpaFlatBuffer;


}


void PowModN (mpz_t *output, const mpz_t *input, const mpz_t *power, const mpz_t *n, CpaInstanceHandle *pCyInstHandle) {

 	// mpz_powm(output.data, input.data, power.data, n.data);

 	// struct timeval t_val;
 	// gettimeofday(&t_val, NULL);
 	// printf("start, now, sec=%ld m_sec=%d \n", t_val.tv_sec, t_val.tv_usec);
 	// long sec = t_val.tv_sec;
 	// time_t t_sec = (time_t)sec;
 	// printf("date:%s", ctime(&t_sec));		

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
 		//printf("start, now, sec=%ld m_sec=%d \n", t_val.tv_sec, t_val.tv_usec);
 		//long sec = t_val.tv_sec;
 		//time_t t_sec = (time_t)sec;
 		//printf("date:%s", ctime(&t_sec));	

 		result_flat_data = ModExp(	input_char_data, input_count,
 			power_char_data, power_count,
 			n_char_data, n_count,
			pCyInstHandle);

 		//struct timeval t_val_end;
 		//gettimeofday(&t_val_end, NULL);
 		//struct timeval t_result;
 		//timersub(&t_val_end, &t_val, &t_result);
 		//double consume = t_result.tv_sec + (1.0 * t_result.tv_usec)/1000000;
 		//printf("%d. -------------- end.elapsed time= %fs \n\n", count, consume);
 		//count++;

 		// mpz_t result_mpz_data;
 		data_import((char*)(result_flat_data->pData), result_mpz_data, 	(size_t)(result_flat_data->dataLenInBytes));

 		mpz_set(output, result_mpz_data);
 	}
 	else if((*power)[0]._mp_size < 0)
 	{
 		//struct timeval t_val;
 		//gettimeofday(&t_val, NULL);
 		//printf("start, now, sec=%ld m_sec=%d \n", t_val.tv_sec, t_val.tv_usec);
 		//long sec = t_val.tv_sec;
 		//time_t t_sec = (time_t)sec;
 		//printf("date:%s", ctime(&t_sec));


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
 		//printf("%d. -------------- end.elapsed time (negative need modInv & modExp)= %fs \n\n", count, consume);
 		//count++;

 		data_import((char*)(result_flat_data->pData), result_mpz_data, 	(size_t)(result_flat_data->dataLenInBytes));

 		mpz_set(output, result_mpz_data);
 	}
 	else
 	{
 		mpz_set_ui(output, 1);
 	}


 	//import
 	// mpz_t power_mpz_data, result_mpz_data;
 	// data_import(power_char_data, power_mpz_data, power_count);
 	// data_import((char*)(result_flat_data->pData), result_mpz_data, 	size_t(result_flat_data->dataLenInBytes));

 	// // output.data = &result_mpz_data;
 	// mpz_set(output.data, result_mpz_data);

 	//std::cout<<"end of BigIntegerGmp::PowModN ."<<std::endl;
	printf("end of PowModN !\n");

 	// struct timeval t_val_end;
 	// gettimeofday(&t_val_end, NULL);
 	// struct timeval t_result;
 	// timersub(&t_val_end, &t_val, &t_result);
 	// double consume = t_result.tv_sec + (1.0 * t_result.tv_usec)/1000000;
 	// printf("%d. -------------- end.elapsed time= %fs \n\n", count, consume);
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