/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE415_Double_Free__malloc_free_wchar_t_45.c
Label Definition File: CWE415_Double_Free__malloc_free.label.xml
Template File: sources-sinks-45.tmpl.c
*/
/*
 * @description
 * CWE: 415 Double Free
 * BadSource:  Allocate data using malloc() and Deallocate data using free()
 * GoodSource: Allocate data using malloc()
 * Sinks:
 *    GoodSink: do nothing
 *    BadSink : Deallocate data using free()
 * Flow Variant: 45 Data flow: data passed as a static global variable from one function to another in the same source file
 *
 * */

#include "std_testcase.h"

#include <wchar.h>

static wchar_t * CWE415_Double_Free__malloc_free_wchar_t_45_badData;
static wchar_t * CWE415_Double_Free__malloc_free_wchar_t_45_goodG2BData;
static wchar_t * CWE415_Double_Free__malloc_free_wchar_t_45_goodB2GData;

#ifndef OMITBAD

static void badSink()
{
    wchar_t * data = CWE415_Double_Free__malloc_free_wchar_t_45_badData;
    /* POTENTIAL FLAW: Possibly freeing memory twice */
    free(data);
}

void CWE415_Double_Free__malloc_free_wchar_t_45_bad()
{
    wchar_t * data;
    /* Initialize data */
    data = NULL;
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    /* POTENTIAL FLAW: Free data in the source - the bad sink frees data as well */
    free(data);
    CWE415_Double_Free__malloc_free_wchar_t_45_badData = data;
    badSink();
}

#endif /* OMITBAD */

#ifndef OMITGOOD

/* goodG2B() uses the GoodSource with the BadSink */
static void goodG2BSink()
{
    wchar_t * data = CWE415_Double_Free__malloc_free_wchar_t_45_goodG2BData;
    /* POTENTIAL FLAW: Possibly freeing memory twice */
    free(data);
}

static void goodG2B()
{
    wchar_t * data;
    /* Initialize data */
    data = NULL;
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    /* FIX: Do NOT free data in the source - the bad sink frees data */
    CWE415_Double_Free__malloc_free_wchar_t_45_goodG2BData = data;
    goodG2BSink();
}

/* goodB2G() uses the BadSource with the GoodSink */
static void goodB2GSink()
{
    wchar_t * data = CWE415_Double_Free__malloc_free_wchar_t_45_goodB2GData;
    /* do nothing */
    /* FIX: Don't attempt to free the memory */
    ; /* empty statement needed for some flow variants */
}

static void goodB2G()
{
    wchar_t * data;
    /* Initialize data */
    data = NULL;
    data = (wchar_t *)malloc(100*sizeof(wchar_t));
    /* POTENTIAL FLAW: Free data in the source - the bad sink frees data as well */
    free(data);
    CWE415_Double_Free__malloc_free_wchar_t_45_goodB2GData = data;
    goodB2GSink();
}

void CWE415_Double_Free__malloc_free_wchar_t_45_good()
{
    goodG2B();
    goodB2G();
}

#endif /* OMITGOOD */

/* Below is the main(). It is only used when building this testcase on
   its own for testing or for building a binary to use in testing binary
   analysis tools. It is not used when compiling all the testcases as one
   application, which is how source code analysis tools are tested. */
#ifdef INCLUDEMAIN

int main(int argc, char * argv[])
{
    /* seed randomness */
    srand( (unsigned)time(NULL) );
#ifndef OMITGOOD
    printLine("Calling good()...");
    CWE415_Double_Free__malloc_free_wchar_t_45_good();
    printLine("Finished good()");
#endif /* OMITGOOD */
#ifndef OMITBAD
    printLine("Calling bad()...");
    CWE415_Double_Free__malloc_free_wchar_t_45_bad();
    printLine("Finished bad()");
#endif /* OMITBAD */
    return 0;
}

#endif