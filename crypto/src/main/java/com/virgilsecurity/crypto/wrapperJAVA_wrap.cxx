/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <cstdlib>



#ifndef SWIGJAVA
#define SWIGJAVA
#endif

#define SWIG_DIRECTORS


#ifdef __cplusplus
/* SwigValueWrapper is described in swig.swg */
template<typename T> class SwigValueWrapper {
  struct SwigMovePointer {
    T *ptr;
    SwigMovePointer(T *p) : ptr(p) { }
    ~SwigMovePointer() { delete ptr; }
    SwigMovePointer& operator=(SwigMovePointer& rhs) { T* oldptr = ptr; ptr = 0; delete oldptr; ptr = rhs.ptr; rhs.ptr = 0; return *this; }
  } pointer;
  SwigValueWrapper& operator=(const SwigValueWrapper<T>& rhs);
  SwigValueWrapper(const SwigValueWrapper<T>& rhs);
public:
  SwigValueWrapper() : pointer(0) { }
  SwigValueWrapper& operator=(const T& t) { SwigMovePointer tmp(new T(t)); pointer = tmp; return *this; }
  operator T&() const { return *pointer.ptr; }
  T *operator&() { return pointer.ptr; }
};

template <typename T> T SwigValueInit() {
  return T();
}
#endif

/* -----------------------------------------------------------------------------
 *  This section contains generic SWIG labels for method/variable
 *  declarations/attributes, and other compiler dependent labels.
 * ----------------------------------------------------------------------------- */

/* template workaround for compilers that cannot correctly implement the C++ standard */
#ifndef SWIGTEMPLATEDISAMBIGUATOR
# if defined(__SUNPRO_CC) && (__SUNPRO_CC <= 0x560)
#  define SWIGTEMPLATEDISAMBIGUATOR template
# elif defined(__HP_aCC)
/* Needed even with `aCC -AA' when `aCC -V' reports HP ANSI C++ B3910B A.03.55 */
/* If we find a maximum version that requires this, the test would be __HP_aCC <= 35500 for A.03.55 */
#  define SWIGTEMPLATEDISAMBIGUATOR template
# else
#  define SWIGTEMPLATEDISAMBIGUATOR
# endif
#endif

/* inline attribute */
#ifndef SWIGINLINE
# if defined(__cplusplus) || (defined(__GNUC__) && !defined(__STRICT_ANSI__))
#   define SWIGINLINE inline
# else
#   define SWIGINLINE
# endif
#endif

/* attribute recognised by some compilers to avoid 'unused' warnings */
#ifndef SWIGUNUSED
# if defined(__GNUC__)
#   if !(defined(__cplusplus)) || (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4))
#     define SWIGUNUSED __attribute__ ((__unused__))
#   else
#     define SWIGUNUSED
#   endif
# elif defined(__ICC)
#   define SWIGUNUSED __attribute__ ((__unused__))
# else
#   define SWIGUNUSED
# endif
#endif

#ifndef SWIG_MSC_UNSUPPRESS_4505
# if defined(_MSC_VER)
#   pragma warning(disable : 4505) /* unreferenced local function has been removed */
# endif
#endif

#ifndef SWIGUNUSEDPARM
# ifdef __cplusplus
#   define SWIGUNUSEDPARM(p)
# else
#   define SWIGUNUSEDPARM(p) p SWIGUNUSED
# endif
#endif

/* internal SWIG method */
#ifndef SWIGINTERN
# define SWIGINTERN static SWIGUNUSED
#endif

/* internal inline SWIG method */
#ifndef SWIGINTERNINLINE
# define SWIGINTERNINLINE SWIGINTERN SWIGINLINE
#endif

/* exporting methods */
#if defined(__GNUC__)
#  if (__GNUC__ >= 4) || (__GNUC__ == 3 && __GNUC_MINOR__ >= 4)
#    ifndef GCC_HASCLASSVISIBILITY
#      define GCC_HASCLASSVISIBILITY
#    endif
#  endif
#endif

#ifndef SWIGEXPORT
# if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#   if defined(STATIC_LINKED)
#     define SWIGEXPORT
#   else
#     define SWIGEXPORT __declspec(dllexport)
#   endif
# else
#   if defined(__GNUC__) && defined(GCC_HASCLASSVISIBILITY)
#     define SWIGEXPORT __attribute__ ((visibility("default")))
#   else
#     define SWIGEXPORT
#   endif
# endif
#endif

/* calling conventions for Windows */
#ifndef SWIGSTDCALL
# if defined(_WIN32) || defined(__WIN32__) || defined(__CYGWIN__)
#   define SWIGSTDCALL __stdcall
# else
#   define SWIGSTDCALL
# endif
#endif

/* Deal with Microsoft's attempt at deprecating C standard runtime functions */
#if !defined(SWIG_NO_CRT_SECURE_NO_DEPRECATE) && defined(_MSC_VER) && !defined(_CRT_SECURE_NO_DEPRECATE)
# define _CRT_SECURE_NO_DEPRECATE
#endif

/* Deal with Microsoft's attempt at deprecating methods in the standard C++ library */
#if !defined(SWIG_NO_SCL_SECURE_NO_DEPRECATE) && defined(_MSC_VER) && !defined(_SCL_SECURE_NO_DEPRECATE)
# define _SCL_SECURE_NO_DEPRECATE
#endif

/* Deal with Apple's deprecated 'AssertMacros.h' from Carbon-framework */
#if defined(__APPLE__) && !defined(__ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES)
# define __ASSERT_MACROS_DEFINE_VERSIONS_WITHOUT_UNDERSCORES 0
#endif

/* Intel's compiler complains if a variable which was never initialised is
 * cast to void, which is a common idiom which we use to indicate that we
 * are aware a variable isn't used.  So we just silence that warning.
 * See: https://github.com/swig/swig/issues/192 for more discussion.
 */
#ifdef __INTEL_COMPILER
# pragma warning disable 592
#endif


/* Fix for jlong on some versions of gcc on Windows */
#if defined(__GNUC__) && !defined(__INTEL_COMPILER)
  typedef long long __int64;
#endif

/* Fix for jlong on 64-bit x86 Solaris */
#if defined(__x86_64)
# ifdef _LP64
#   undef _LP64
# endif
#endif

#include <jni.h>
#include <stdlib.h>
#include <string.h>


/* Support for throwing Java exceptions */
typedef enum {
  SWIG_JavaOutOfMemoryError = 1, 
  SWIG_JavaIOException, 
  SWIG_JavaRuntimeException, 
  SWIG_JavaIndexOutOfBoundsException,
  SWIG_JavaArithmeticException,
  SWIG_JavaIllegalArgumentException,
  SWIG_JavaNullPointerException,
  SWIG_JavaDirectorPureVirtual,
  SWIG_JavaUnknownError
} SWIG_JavaExceptionCodes;

typedef struct {
  SWIG_JavaExceptionCodes code;
  const char *java_exception;
} SWIG_JavaExceptions_t;


static void SWIGUNUSED SWIG_JavaThrowException(JNIEnv *jenv, SWIG_JavaExceptionCodes code, const char *msg) {
  jclass excep;
  static const SWIG_JavaExceptions_t java_exceptions[] = {
    { SWIG_JavaOutOfMemoryError, "java/lang/OutOfMemoryError" },
    { SWIG_JavaIOException, "java/io/IOException" },
    { SWIG_JavaRuntimeException, "java/lang/RuntimeException" },
    { SWIG_JavaIndexOutOfBoundsException, "java/lang/IndexOutOfBoundsException" },
    { SWIG_JavaArithmeticException, "java/lang/ArithmeticException" },
    { SWIG_JavaIllegalArgumentException, "java/lang/IllegalArgumentException" },
    { SWIG_JavaNullPointerException, "java/lang/NullPointerException" },
    { SWIG_JavaDirectorPureVirtual, "java/lang/RuntimeException" },
    { SWIG_JavaUnknownError,  "java/lang/UnknownError" },
    { (SWIG_JavaExceptionCodes)0,  "java/lang/UnknownError" }
  };
  const SWIG_JavaExceptions_t *except_ptr = java_exceptions;

  while (except_ptr->code != code && except_ptr->code)
    except_ptr++;

  jenv->ExceptionClear();
  excep = jenv->FindClass(except_ptr->java_exception);
  if (excep)
    jenv->ThrowNew(excep, msg);
}


/* Contract support */

#define SWIG_contract_assert(nullreturn, expr, msg) if (!(expr)) {SWIG_JavaThrowException(jenv, SWIG_JavaIllegalArgumentException, msg); return nullreturn; } else

/*  Errors in SWIG */
#define  SWIG_UnknownError    	   -1
#define  SWIG_IOError        	   -2
#define  SWIG_RuntimeError   	   -3
#define  SWIG_IndexError     	   -4
#define  SWIG_TypeError      	   -5
#define  SWIG_DivisionByZero 	   -6
#define  SWIG_OverflowError  	   -7
#define  SWIG_SyntaxError    	   -8
#define  SWIG_ValueError     	   -9
#define  SWIG_SystemError    	   -10
#define  SWIG_AttributeError 	   -11
#define  SWIG_MemoryError    	   -12
#define  SWIG_NullReferenceError   -13



/* -----------------------------------------------------------------------------
 * director_common.swg
 *
 * This file contains support for director classes which is common between
 * languages.
 * ----------------------------------------------------------------------------- */

/*
  Use -DSWIG_DIRECTOR_STATIC if you prefer to avoid the use of the
  'Swig' namespace. This could be useful for multi-modules projects.
*/
#ifdef SWIG_DIRECTOR_STATIC
/* Force anonymous (static) namespace */
#define Swig
#endif
/* -----------------------------------------------------------------------------
 * director.swg
 *
 * This file contains support for director classes so that Java proxy
 * methods can be called from C++.
 * ----------------------------------------------------------------------------- */

#if defined(DEBUG_DIRECTOR_OWNED) || defined(DEBUG_DIRECTOR_EXCEPTION)
#include <iostream>
#endif

#include <exception>

namespace Swig {

  /* Java object wrapper */
  class JObjectWrapper {
  public:
    JObjectWrapper() : jthis_(NULL), weak_global_(true) {
    }

    ~JObjectWrapper() {
      jthis_ = NULL;
      weak_global_ = true;
    }

    bool set(JNIEnv *jenv, jobject jobj, bool mem_own, bool weak_global) {
      if (!jthis_) {
        weak_global_ = weak_global || !mem_own; // hold as weak global if explicitly requested or not owned
        if (jobj)
          jthis_ = weak_global_ ? jenv->NewWeakGlobalRef(jobj) : jenv->NewGlobalRef(jobj);
#if defined(DEBUG_DIRECTOR_OWNED)
        std::cout << "JObjectWrapper::set(" << jobj << ", " << (weak_global ? "weak_global" : "global_ref") << ") -> " << jthis_ << std::endl;
#endif
        return true;
      } else {
#if defined(DEBUG_DIRECTOR_OWNED)
        std::cout << "JObjectWrapper::set(" << jobj << ", " << (weak_global ? "weak_global" : "global_ref") << ") -> already set" << std::endl;
#endif
        return false;
      }
    }

    jobject get(JNIEnv *jenv) const {
#if defined(DEBUG_DIRECTOR_OWNED)
      std::cout << "JObjectWrapper::get(";
      if (jthis_)
        std::cout << jthis_;
      else
        std::cout << "null";
      std::cout << ") -> return new local ref" << std::endl;
#endif
      return (jthis_ ? jenv->NewLocalRef(jthis_) : jthis_);
    }

    void release(JNIEnv *jenv) {
#if defined(DEBUG_DIRECTOR_OWNED)
      std::cout << "JObjectWrapper::release(" << jthis_ << "): " << (weak_global_ ? "weak global ref" : "global ref") << std::endl;
#endif
      if (jthis_) {
        if (weak_global_) {
          if (jenv->IsSameObject(jthis_, NULL) == JNI_FALSE)
            jenv->DeleteWeakGlobalRef((jweak)jthis_);
        } else
          jenv->DeleteGlobalRef(jthis_);
      }

      jthis_ = NULL;
      weak_global_ = true;
    }

    /* Only call peek if you know what you are doing wrt to weak/global references */
    jobject peek() {
      return jthis_;
    }

    /* Java proxy releases ownership of C++ object, C++ object is now
       responsible for destruction (creates NewGlobalRef to pin Java proxy) */
    void java_change_ownership(JNIEnv *jenv, jobject jself, bool take_or_release) {
      if (take_or_release) {  /* Java takes ownership of C++ object's lifetime. */
        if (!weak_global_) {
          jenv->DeleteGlobalRef(jthis_);
          jthis_ = jenv->NewWeakGlobalRef(jself);
          weak_global_ = true;
        }
      } else {
	/* Java releases ownership of C++ object's lifetime */
        if (weak_global_) {
          jenv->DeleteWeakGlobalRef((jweak)jthis_);
          jthis_ = jenv->NewGlobalRef(jself);
          weak_global_ = false;
        }
      }
    }

  private:
    /* pointer to Java object */
    jobject jthis_;
    /* Local or global reference flag */
    bool weak_global_;
  };

  /* Local JNI reference deleter */
  class LocalRefGuard {
    JNIEnv *jenv_;
    jobject jobj_;

    // non-copyable
    LocalRefGuard(const LocalRefGuard &);
    LocalRefGuard &operator=(const LocalRefGuard &);
  public:
    LocalRefGuard(JNIEnv *jenv, jobject jobj): jenv_(jenv), jobj_(jobj) {}
    ~LocalRefGuard() {
      if (jobj_)
        jenv_->DeleteLocalRef(jobj_);
    }
  };

  /* director base class */
  class Director {
    /* pointer to Java virtual machine */
    JavaVM *swig_jvm_;

  protected:
#if defined (_MSC_VER) && (_MSC_VER<1300)
    class JNIEnvWrapper;
    friend class JNIEnvWrapper;
#endif
    /* Utility class for managing the JNI environment */
    class JNIEnvWrapper {
      const Director *director_;
      JNIEnv *jenv_;
      int env_status;
    public:
      JNIEnvWrapper(const Director *director) : director_(director), jenv_(0), env_status(0) {
#if defined(__ANDROID__)
        JNIEnv **jenv = &jenv_;
#else
        void **jenv = (void **)&jenv_;
#endif
        env_status = director_->swig_jvm_->GetEnv((void **)&jenv_, JNI_VERSION_1_2);
#if defined(SWIG_JAVA_ATTACH_CURRENT_THREAD_AS_DAEMON)
        // Attach a daemon thread to the JVM. Useful when the JVM should not wait for
        // the thread to exit upon shutdown. Only for jdk-1.4 and later.
        director_->swig_jvm_->AttachCurrentThreadAsDaemon(jenv, NULL);
#else
        director_->swig_jvm_->AttachCurrentThread(jenv, NULL);
#endif
      }
      ~JNIEnvWrapper() {
#if !defined(SWIG_JAVA_NO_DETACH_CURRENT_THREAD)
        // Some JVMs, eg jdk-1.4.2 and lower on Solaris have a bug and crash with the DetachCurrentThread call.
        // However, without this call, the JVM hangs on exit when the thread was not created by the JVM and creates a memory leak.
        if (env_status == JNI_EDETACHED)
          director_->swig_jvm_->DetachCurrentThread();
#endif
      }
      JNIEnv *getJNIEnv() const {
        return jenv_;
      }
    };

    /* Java object wrapper */
    JObjectWrapper swig_self_;

    /* Disconnect director from Java object */
    void swig_disconnect_director_self(const char *disconn_method) {
      JNIEnvWrapper jnienv(this) ;
      JNIEnv *jenv = jnienv.getJNIEnv() ;
      jobject jobj = swig_self_.get(jenv);
      LocalRefGuard ref_deleter(jenv, jobj);
#if defined(DEBUG_DIRECTOR_OWNED)
      std::cout << "Swig::Director::disconnect_director_self(" << jobj << ")" << std::endl;
#endif
      if (jobj && jenv->IsSameObject(jobj, NULL) == JNI_FALSE) {
        jmethodID disconn_meth = jenv->GetMethodID(jenv->GetObjectClass(jobj), disconn_method, "()V");
        if (disconn_meth) {
#if defined(DEBUG_DIRECTOR_OWNED)
          std::cout << "Swig::Director::disconnect_director_self upcall to " << disconn_method << std::endl;
#endif
          jenv->CallVoidMethod(jobj, disconn_meth);
        }
      }
    }

  public:
    Director(JNIEnv *jenv) : swig_jvm_((JavaVM *) NULL), swig_self_() {
      /* Acquire the Java VM pointer */
      jenv->GetJavaVM(&swig_jvm_);
    }

    virtual ~Director() {
      JNIEnvWrapper jnienv(this) ;
      JNIEnv *jenv = jnienv.getJNIEnv() ;
      swig_self_.release(jenv);
    }

    bool swig_set_self(JNIEnv *jenv, jobject jself, bool mem_own, bool weak_global) {
      return swig_self_.set(jenv, jself, mem_own, weak_global);
    }

    jobject swig_get_self(JNIEnv *jenv) const {
      return swig_self_.get(jenv);
    }

    // Change C++ object's ownership, relative to Java
    void swig_java_change_ownership(JNIEnv *jenv, jobject jself, bool take_or_release) {
      swig_self_.java_change_ownership(jenv, jself, take_or_release);
    }
  };

  // Zero initialized bool array
  template<size_t N> class BoolArray {
    bool array_[N];
  public:
    BoolArray() {
      memset(array_, 0, sizeof(array_));
    }
    bool& operator[](size_t n) {
      return array_[n];
    }
    bool operator[](size_t n) const {
      return array_[n];
    }
  };

  // Utility classes and functions for exception handling.

  // Simple holder for a Java string during exception handling, providing access to a c-style string
  class JavaString {
  public:
    JavaString(JNIEnv *jenv, jstring jstr) : jenv_(jenv), jstr_(jstr), cstr_(0) {
      if (jenv_ && jstr_)
	cstr_ = (const char *) jenv_->GetStringUTFChars(jstr_, NULL);
    }

    ~JavaString() {
      if (jenv_ && jstr_ && cstr_)
	jenv_->ReleaseStringUTFChars(jstr_, cstr_);
    }

    const char *c_str(const char *null_string = "null JavaString") const {
      return cstr_ ? cstr_ : null_string;
    }

  private:
    // non-copyable
    JavaString(const JavaString &);
    JavaString &operator=(const JavaString &);

    JNIEnv *jenv_;
    jstring jstr_;
    const char *cstr_;
  };

  // Helper class to extract the exception message from a Java throwable
  class JavaExceptionMessage {
  public:
    JavaExceptionMessage(JNIEnv *jenv, jthrowable throwable) : message_(jenv, exceptionMessageFromThrowable(jenv, throwable)) {
    }

    const char *message() const {
      return message_.c_str("Could not get exception message in JavaExceptionMessage");
    }

  private:
    // non-copyable
    JavaExceptionMessage(const JavaExceptionMessage &);
    JavaExceptionMessage &operator=(const JavaExceptionMessage &);

    // Get exception message by calling Java method Throwable.getMessage()
    static jstring exceptionMessageFromThrowable(JNIEnv *jenv, jthrowable throwable) {
      jstring jmsg = NULL;
      if (jenv && throwable) {
	jenv->ExceptionClear(); // Cannot invoke methods with any pending exceptions
	jclass throwclz = jenv->GetObjectClass(throwable);
	if (throwclz) {
	  // All Throwable classes have a getMessage() method, so call it to extract the exception message
	  jmethodID getMessageMethodID = jenv->GetMethodID(throwclz, "getMessage", "()Ljava/lang/String;");
	  if (getMessageMethodID)
	    jmsg = (jstring)jenv->CallObjectMethod(throwable, getMessageMethodID);
	}
	if (jmsg == NULL && jenv->ExceptionCheck())
	  jenv->ExceptionClear();
      }
      return jmsg;
    }

    JavaString message_;
  };

  // C++ Exception class for handling Java exceptions thrown during a director method Java upcall
  class DirectorException : public std::exception {
  public:

    // Construct exception from a Java throwable
    DirectorException(JNIEnv *jenv, jthrowable throwable) : classname_(0), msg_(0) {

      // Call Java method Object.getClass().getName() to obtain the throwable's class name (delimited by '/')
      if (throwable) {
	jclass throwclz = jenv->GetObjectClass(throwable);
	if (throwclz) {
	  jclass clzclz = jenv->GetObjectClass(throwclz);
	  if (clzclz) {
	    jmethodID getNameMethodID = jenv->GetMethodID(clzclz, "getName", "()Ljava/lang/String;");
	    if (getNameMethodID) {
	      jstring jstr_classname = (jstring)(jenv->CallObjectMethod(throwclz, getNameMethodID));
              // Copy strings, since there is no guarantee that jenv will be active when handled
              if (jstr_classname) {
                JavaString jsclassname(jenv, jstr_classname);
                const char *classname = jsclassname.c_str(0);
                if (classname)
                  classname_ = copypath(classname);
              }
	    }
	  }
	}
      }

      JavaExceptionMessage exceptionmsg(jenv, throwable);
      msg_ = copystr(exceptionmsg.message());
    }

    // More general constructor for handling as a java.lang.RuntimeException
    DirectorException(const char *msg) : classname_(0), msg_(copystr(msg ? msg : "Unspecified DirectorException message")) {
    }

    ~DirectorException() throw() {
      delete[] classname_;
      delete[] msg_;
    }

    const char *what() const throw() {
      return msg_;
    }

    // Reconstruct and raise/throw the Java Exception that caused the DirectorException
    // Note that any error in the JNI exception handling results in a Java RuntimeException
    void raiseJavaException(JNIEnv *jenv) const {
      if (jenv) {
	jenv->ExceptionClear();

	jmethodID ctorMethodID = 0;
	jclass throwableclass = 0;
        if (classname_) {
          throwableclass = jenv->FindClass(classname_);
          if (throwableclass)
            ctorMethodID = jenv->GetMethodID(throwableclass, "<init>", "(Ljava/lang/String;)V");
	}

	if (ctorMethodID) {
	  jenv->ThrowNew(throwableclass, what());
	} else {
	  SWIG_JavaThrowException(jenv, SWIG_JavaRuntimeException, what());
	}
      }
    }

  private:
    static char *copypath(const char *srcmsg) {
      char *target = copystr(srcmsg);
      for (char *c=target; *c; ++c) {
        if ('.' == *c)
          *c = '/';
      }
      return target;
    }

    static char *copystr(const char *srcmsg) {
      char *target = 0;
      if (srcmsg) {
	size_t msglen = strlen(srcmsg) + 1;
	target = new char[msglen];
	strncpy(target, srcmsg, msglen);
      }
      return target;
    }

    const char *classname_;
    const char *msg_;
  };

  // Helper method to determine if a Java throwable matches a particular Java class type
  SWIGINTERN bool ExceptionMatches(JNIEnv *jenv, jthrowable throwable, const char *classname) {
    bool matches = false;

    if (throwable && jenv && classname) {
      // Exceptions need to be cleared for correct behavior.
      // The caller of ExceptionMatches should restore pending exceptions if desired -
      // the caller already has the throwable.
      jenv->ExceptionClear();

      jclass clz = jenv->FindClass(classname);
      if (clz) {
	jclass classclz = jenv->GetObjectClass(clz);
	jmethodID isInstanceMethodID = jenv->GetMethodID(classclz, "isInstance", "(Ljava/lang/Object;)Z");
	if (isInstanceMethodID) {
	  matches = jenv->CallBooleanMethod(clz, isInstanceMethodID, throwable) != 0;
	}
      }

#if defined(DEBUG_DIRECTOR_EXCEPTION)
      if (jenv->ExceptionCheck()) {
        // Typically occurs when an invalid classname argument is passed resulting in a ClassNotFoundException
        JavaExceptionMessage exc(jenv, jenv->ExceptionOccurred());
        std::cout << "Error: ExceptionMatches: class '" << classname << "' : " << exc.message() << std::endl;
      }
#endif
    }
    return matches;
  }
}

namespace Swig {
  namespace {
    jclass jclass_virgil_crypto_javaJNI = NULL;
    jmethodID director_method_ids[4];
  }
}

#define VIRGIL_CRYPTO_FEATURE_LOW_LEVEL_WRAP 1


SWIGINTERN void SWIG_JavaException(JNIEnv *jenv, int code, const char *msg) {
  SWIG_JavaExceptionCodes exception_code = SWIG_JavaUnknownError;
  switch(code) {
  case SWIG_MemoryError:
    exception_code = SWIG_JavaOutOfMemoryError;
    break;
  case SWIG_IOError:
    exception_code = SWIG_JavaIOException;
    break;
  case SWIG_SystemError:
  case SWIG_RuntimeError:
    exception_code = SWIG_JavaRuntimeException;
    break;
  case SWIG_OverflowError:
  case SWIG_IndexError:
    exception_code = SWIG_JavaIndexOutOfBoundsException;
    break;
  case SWIG_DivisionByZero:
    exception_code = SWIG_JavaArithmeticException;
    break;
  case SWIG_SyntaxError:
  case SWIG_ValueError:
  case SWIG_TypeError:
    exception_code = SWIG_JavaIllegalArgumentException;
    break;
  case SWIG_UnknownError:
  default:
    exception_code = SWIG_JavaUnknownError;
    break;
  }
  SWIG_JavaThrowException(jenv, exception_code, msg);
}


#include <typeinfo>
#include <stdexcept>


#include <typeinfo>
#include <stdexcept>


#include <string>


#include <vector>


#include <virgil/crypto/VirgilCryptoException.h>


#include <sstream>
#include <exception>
static std::string backtrace_message(const std::exception& exception, int level = 0) {
    std::ostringstream sstr;
    sstr << exception.what();
    try {
        std::rethrow_if_nested(exception);
    } catch(const std::exception& nested) {
        sstr << "\n" << backtrace_message(nested, level);
    } catch(...) {}
    return sstr.str();
}


#include <virgil/crypto/VirgilByteArray.h>


#include <virgil/crypto/VirgilVersion.h>


#include <virgil/crypto/VirgilDataSource.h>


#include <virgil/crypto/VirgilDataSink.h>


#include <virgil/crypto/foundation/asn1/VirgilAsn1Compatible.h>


#include <virgil/crypto/VirgilKeyPair.h>


using virgil::crypto::VirgilKeyPair;


#include <virgil/crypto/foundation/asn1/VirgilAsn1Reader.h>


#include <virgil/crypto/foundation/asn1/VirgilAsn1Writer.h>


#include <virgil/crypto/foundation/cms/VirgilCMSKeyTransRecipient.h>


#include <virgil/crypto/foundation/cms/VirgilCMSPasswordRecipient.h>


#include <virgil/crypto/foundation/cms/VirgilCMSEncryptedContent.h>


#include <virgil/crypto/foundation/cms/VirgilCMSEnvelopedData.h>


#include <virgil/crypto/foundation/cms/VirgilCMSContent.h>


#include <virgil/crypto/foundation/cms/VirgilCMSContentInfo.h>


#include <virgil/crypto/foundation/VirgilHash.h>


#include <virgil/crypto/foundation/VirgilKDF.h>


using virgil::crypto::foundation::VirgilKDF;


#include <virgil/crypto/foundation/VirgilSymmetricCipher.h>


#include <virgil/crypto/foundation/VirgilAsymmetricCipher.h>


#include <virgil/crypto/foundation/VirgilPBE.h>


using virgil::crypto::foundation::VirgilPBE;


#include <virgil/crypto/foundation/VirgilHKDF.h>


#include <virgil/crypto/foundation/VirgilBase64.h>


#include <virgil/crypto/foundation/VirgilPBKDF.h>


#include <virgil/crypto/foundation/VirgilRandom.h>


using virgil::crypto::foundation::VirgilHash;


using virgil::crypto::foundation::VirgilPBKDF;


#include <virgil/crypto/VirgilCustomParams.h>


#include <virgil/crypto/VirgilCipherBase.h>


#include <virgil/crypto/VirgilCipher.h>


#include <virgil/crypto/VirgilChunkCipher.h>


#include <virgil/crypto/VirgilSignerBase.h>


#include <virgil/crypto/VirgilSigner.h>


#include <virgil/crypto/VirgilStreamSigner.h>


#include <virgil/crypto/VirgilStreamCipher.h>


#include <virgil/crypto/VirgilTinyCipher.h>


#include <virgil/crypto/VirgilByteArrayUtils.h>


#include <virgil/crypto/pfs/VirgilPFSEncryptedMessage.h>


#include <virgil/crypto/pfs/VirgilPFSPublicKey.h>


#include <virgil/crypto/pfs/VirgilPFSPrivateKey.h>


#include <virgil/crypto/pfs/VirgilPFSInitiatorPublicInfo.h>


#include <virgil/crypto/pfs/VirgilPFSInitiatorPrivateInfo.h>


#include <virgil/crypto/pfs/VirgilPFSResponderPublicInfo.h>


#include <virgil/crypto/pfs/VirgilPFSResponderPrivateInfo.h>


#include <virgil/crypto/pfs/VirgilPFSSession.h>


#include <virgil/crypto/pfs/VirgilPFS.h>



/* ---------------------------------------------------
 * C++ director class methods
 * --------------------------------------------------- */

#include "wrapperJAVA_wrap.h"

SwigDirector_VirgilDataSource::SwigDirector_VirgilDataSource(JNIEnv *jenv) : virgil::crypto::VirgilDataSource(), Swig::Director(jenv) {
}

bool SwigDirector_VirgilDataSource::hasData() {
  bool c_result = SwigValueInit< bool >() ;
  jboolean jresult = 0 ;
  JNIEnvWrapper swigjnienv(this) ;
  JNIEnv * jenv = swigjnienv.getJNIEnv() ;
  jobject swigjobj = (jobject) NULL ;
  
  if (!swig_override[0]) {
    SWIG_JavaThrowException(JNIEnvWrapper(this).getJNIEnv(), SWIG_JavaDirectorPureVirtual, "Attempted to invoke pure virtual method virgil::crypto::VirgilDataSource::hasData.");
    return c_result;
  }
  swigjobj = swig_get_self(jenv);
  if (swigjobj && jenv->IsSameObject(swigjobj, NULL) == JNI_FALSE) {
    jresult = (jboolean) jenv->CallStaticBooleanMethod(Swig::jclass_virgil_crypto_javaJNI, Swig::director_method_ids[0], swigjobj);
    jthrowable swigerror = jenv->ExceptionOccurred();
    if (swigerror) {
      jenv->ExceptionClear();
      throw Swig::DirectorException(jenv, swigerror);
    }
    
    c_result = jresult ? true : false; 
  } else {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null upcall object in virgil::crypto::VirgilDataSource::hasData ");
  }
  if (swigjobj) jenv->DeleteLocalRef(swigjobj);
  return c_result;
}

virgil::crypto::VirgilByteArray SwigDirector_VirgilDataSource::read() {
  virgil::crypto::VirgilByteArray c_result ;
  jbyteArray jresult = 0 ;
  JNIEnvWrapper swigjnienv(this) ;
  JNIEnv * jenv = swigjnienv.getJNIEnv() ;
  jobject swigjobj = (jobject) NULL ;
  
  if (!swig_override[1]) {
    SWIG_JavaThrowException(JNIEnvWrapper(this).getJNIEnv(), SWIG_JavaDirectorPureVirtual, "Attempted to invoke pure virtual method virgil::crypto::VirgilDataSource::read.");
    return c_result;
  }
  swigjobj = swig_get_self(jenv);
  if (swigjobj && jenv->IsSameObject(swigjobj, NULL) == JNI_FALSE) {
    jresult = (jbyteArray) jenv->CallStaticObjectMethod(Swig::jclass_virgil_crypto_javaJNI, Swig::director_method_ids[1], swigjobj);
    jthrowable swigerror = jenv->ExceptionOccurred();
    if (swigerror) {
      jenv->ExceptionClear();
      throw Swig::DirectorException(jenv, swigerror);
    }
    
    if(!jresult) {
      if (!jenv->ExceptionCheck()) {
        SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
      }
      return c_result;
    }
    Swig::LocalRefGuard jresult_guard(jenv, jresult);
    jbyte *c_result_pdata = (jbyte *)jenv->GetByteArrayElements(jresult, 0);
    size_t c_result_size = (size_t)jenv->GetArrayLength(jresult);
    if (!c_result_pdata) return c_result;
    c_result.assign(c_result_pdata, c_result_pdata + c_result_size);
    jenv->ReleaseByteArrayElements(jresult, c_result_pdata, 0);
    
  } else {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null upcall object in virgil::crypto::VirgilDataSource::read ");
  }
  if (swigjobj) jenv->DeleteLocalRef(swigjobj);
  return c_result;
}

SwigDirector_VirgilDataSource::~SwigDirector_VirgilDataSource() {
  swig_disconnect_director_self("swigDirectorDisconnect");
}


void SwigDirector_VirgilDataSource::swig_connect_director(JNIEnv *jenv, jobject jself, jclass jcls, bool swig_mem_own, bool weak_global) {
  static struct {
    const char *mname;
    const char *mdesc;
    jmethodID base_methid;
  } methods[] = {
    {
      "hasData", "()Z", NULL 
    },
    {
      "read", "()[B", NULL 
    }
  };
  
  static jclass baseclass = 0 ;
  
  if (swig_set_self(jenv, jself, swig_mem_own, weak_global)) {
    if (!baseclass) {
      baseclass = jenv->FindClass("com/virgilsecurity/crypto/VirgilDataSource");
      if (!baseclass) return;
      baseclass = (jclass) jenv->NewGlobalRef(baseclass);
    }
    bool derived = (jenv->IsSameObject(baseclass, jcls) ? false : true);
    for (int i = 0; i < 2; ++i) {
      if (!methods[i].base_methid) {
        methods[i].base_methid = jenv->GetMethodID(baseclass, methods[i].mname, methods[i].mdesc);
        if (!methods[i].base_methid) return;
      }
      swig_override[i] = false;
      if (derived) {
        jmethodID methid = jenv->GetMethodID(jcls, methods[i].mname, methods[i].mdesc);
        swig_override[i] = (methid != methods[i].base_methid);
        jenv->ExceptionClear();
      }
    }
  }
}


SwigDirector_VirgilDataSink::SwigDirector_VirgilDataSink(JNIEnv *jenv) : virgil::crypto::VirgilDataSink(), Swig::Director(jenv) {
}

bool SwigDirector_VirgilDataSink::isGood() {
  bool c_result = SwigValueInit< bool >() ;
  jboolean jresult = 0 ;
  JNIEnvWrapper swigjnienv(this) ;
  JNIEnv * jenv = swigjnienv.getJNIEnv() ;
  jobject swigjobj = (jobject) NULL ;
  
  if (!swig_override[0]) {
    SWIG_JavaThrowException(JNIEnvWrapper(this).getJNIEnv(), SWIG_JavaDirectorPureVirtual, "Attempted to invoke pure virtual method virgil::crypto::VirgilDataSink::isGood.");
    return c_result;
  }
  swigjobj = swig_get_self(jenv);
  if (swigjobj && jenv->IsSameObject(swigjobj, NULL) == JNI_FALSE) {
    jresult = (jboolean) jenv->CallStaticBooleanMethod(Swig::jclass_virgil_crypto_javaJNI, Swig::director_method_ids[2], swigjobj);
    jthrowable swigerror = jenv->ExceptionOccurred();
    if (swigerror) {
      jenv->ExceptionClear();
      throw Swig::DirectorException(jenv, swigerror);
    }
    
    c_result = jresult ? true : false; 
  } else {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null upcall object in virgil::crypto::VirgilDataSink::isGood ");
  }
  if (swigjobj) jenv->DeleteLocalRef(swigjobj);
  return c_result;
}

void SwigDirector_VirgilDataSink::write(virgil::crypto::VirgilByteArray const &data) {
  JNIEnvWrapper swigjnienv(this) ;
  JNIEnv * jenv = swigjnienv.getJNIEnv() ;
  jobject swigjobj = (jobject) NULL ;
  jbyteArray jdata = 0 ;
  
  if (!swig_override[1]) {
    SWIG_JavaThrowException(JNIEnvWrapper(this).getJNIEnv(), SWIG_JavaDirectorPureVirtual, "Attempted to invoke pure virtual method virgil::crypto::VirgilDataSink::write.");
    return;
  }
  swigjobj = swig_get_self(jenv);
  if (swigjobj && jenv->IsSameObject(swigjobj, NULL) == JNI_FALSE) {
    jdata = jenv->NewByteArray((&data)->size());
    jenv->SetByteArrayRegion(jdata, 0, (&data)->size(), (const jbyte *)&data[0]);
    Swig::LocalRefGuard data_refguard(jenv, jdata);
    
    jenv->CallStaticVoidMethod(Swig::jclass_virgil_crypto_javaJNI, Swig::director_method_ids[3], swigjobj, jdata);
    jthrowable swigerror = jenv->ExceptionOccurred();
    if (swigerror) {
      jenv->ExceptionClear();
      throw Swig::DirectorException(jenv, swigerror);
    }
    
  } else {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null upcall object in virgil::crypto::VirgilDataSink::write ");
  }
  if (swigjobj) jenv->DeleteLocalRef(swigjobj);
}

SwigDirector_VirgilDataSink::~SwigDirector_VirgilDataSink() {
  swig_disconnect_director_self("swigDirectorDisconnect");
}


void SwigDirector_VirgilDataSink::swig_connect_director(JNIEnv *jenv, jobject jself, jclass jcls, bool swig_mem_own, bool weak_global) {
  static struct {
    const char *mname;
    const char *mdesc;
    jmethodID base_methid;
  } methods[] = {
    {
      "isGood", "()Z", NULL 
    },
    {
      "write", "([B)V", NULL 
    }
  };
  
  static jclass baseclass = 0 ;
  
  if (swig_set_self(jenv, jself, swig_mem_own, weak_global)) {
    if (!baseclass) {
      baseclass = jenv->FindClass("com/virgilsecurity/crypto/VirgilDataSink");
      if (!baseclass) return;
      baseclass = (jclass) jenv->NewGlobalRef(baseclass);
    }
    bool derived = (jenv->IsSameObject(baseclass, jcls) ? false : true);
    for (int i = 0; i < 2; ++i) {
      if (!methods[i].base_methid) {
        methods[i].base_methid = jenv->GetMethodID(baseclass, methods[i].mname, methods[i].mdesc);
        if (!methods[i].base_methid) return;
      }
      swig_override[i] = false;
      if (derived) {
        jmethodID methid = jenv->GetMethodID(jcls, methods[i].mname, methods[i].mdesc);
        swig_override[i] = (methid != methods[i].base_methid);
        jenv->ExceptionClear();
      }
    }
  }
}



#ifdef __cplusplus
extern "C" {
#endif

SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VIRGIL_1CRYPTO_1FEATURE_1LOW_1LEVEL_1WRAP_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  int result;
  
  (void)jenv;
  (void)jcls;
  result = (int)(1);
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilVersion_1asNumber(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilVersion::asNumber();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilVersion_1asString(JNIEnv *jenv, jclass jcls) {
  jstring jresult = 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilVersion::asString();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilVersion_1majorVersion(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilVersion::majorVersion();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilVersion_1minorVersion(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilVersion::minorVersion();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilVersion_1patchVersion(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilVersion::patchVersion();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilVersion_1fullName(JNIEnv *jenv, jclass jcls) {
  jstring jresult = 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilVersion::fullName();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilVersion(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilVersion *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilVersion *)new virgil::crypto::VirgilVersion();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilVersion **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilVersion(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilVersion *arg1 = (virgil::crypto::VirgilVersion *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilVersion **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSource_1hasData(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilDataSource *arg1 = (virgil::crypto::VirgilDataSource *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilDataSource **)&jarg1; 
  {
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSource_1read(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilDataSource *arg1 = (virgil::crypto::VirgilDataSource *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilDataSource **)&jarg1; 
  {
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilDataSource(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilDataSource *arg1 = (virgil::crypto::VirgilDataSource *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilDataSource **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilDataSource(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilDataSource *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilDataSource *)new SwigDirector_VirgilDataSource(jenv);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilDataSource **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSource_1director_1connect(JNIEnv *jenv, jclass jcls, jobject jself, jlong objarg, jboolean jswig_mem_own, jboolean jweak_global) {
  virgil::crypto::VirgilDataSource *obj = *((virgil::crypto::VirgilDataSource **)&objarg);
  (void)jcls;
  SwigDirector_VirgilDataSource *director = dynamic_cast<SwigDirector_VirgilDataSource *>(obj);
  if (director) {
    director->swig_connect_director(jenv, jself, jenv->GetObjectClass(jself), (jswig_mem_own == JNI_TRUE), (jweak_global == JNI_TRUE));
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSource_1change_1ownership(JNIEnv *jenv, jclass jcls, jobject jself, jlong objarg, jboolean jtake_or_release) {
  virgil::crypto::VirgilDataSource *obj = *((virgil::crypto::VirgilDataSource **)&objarg);
  SwigDirector_VirgilDataSource *director = dynamic_cast<SwigDirector_VirgilDataSource *>(obj);
  (void)jcls;
  if (director) {
    director->swig_java_change_ownership(jenv, jself, jtake_or_release ? true : false);
  }
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSink_1isGood(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilDataSink *arg1 = (virgil::crypto::VirgilDataSink *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilDataSink **)&jarg1; 
  {
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSink_1write(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilDataSink *arg1 = (virgil::crypto::VirgilDataSink *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilDataSink **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilDataSink(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilDataSink *arg1 = (virgil::crypto::VirgilDataSink *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilDataSink **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilDataSink(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilDataSink *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilDataSink *)new SwigDirector_VirgilDataSink(jenv);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilDataSink **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSink_1director_1connect(JNIEnv *jenv, jclass jcls, jobject jself, jlong objarg, jboolean jswig_mem_own, jboolean jweak_global) {
  virgil::crypto::VirgilDataSink *obj = *((virgil::crypto::VirgilDataSink **)&objarg);
  (void)jcls;
  SwigDirector_VirgilDataSink *director = dynamic_cast<SwigDirector_VirgilDataSink *>(obj);
  if (director) {
    director->swig_connect_director(jenv, jself, jenv->GetObjectClass(jself), (jswig_mem_own == JNI_TRUE), (jweak_global == JNI_TRUE));
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilDataSink_1change_1ownership(JNIEnv *jenv, jclass jcls, jobject jself, jlong objarg, jboolean jtake_or_release) {
  virgil::crypto::VirgilDataSink *obj = *((virgil::crypto::VirgilDataSink **)&objarg);
  SwigDirector_VirgilDataSink *director = dynamic_cast<SwigDirector_VirgilDataSink *>(obj);
  (void)jcls;
  if (director) {
    director->swig_java_change_ownership(jenv, jself, jtake_or_release ? true : false);
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Compatible_1toAsn1(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Compatible *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Compatible *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::asn1::VirgilAsn1Compatible const *)arg1)->toAsn1();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Compatible_1fromAsn1(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::asn1::VirgilAsn1Compatible *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Compatible *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->fromAsn1((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilAsn1Compatible(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::asn1::VirgilAsn1Compatible *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Compatible *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generate_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jint jarg1, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair::Type arg1 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  SwigValueWrapper< virgil::crypto::VirgilKeyPair > result;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::VirgilKeyPair::Type)jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generate(arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generate_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jint jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair::Type arg1 ;
  SwigValueWrapper< virgil::crypto::VirgilKeyPair > result;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::VirgilKeyPair::Type)jarg1; 
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generate(arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generateRecommended_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  SwigValueWrapper< virgil::crypto::VirgilKeyPair > result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generateRecommended((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generateRecommended_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  SwigValueWrapper< virgil::crypto::VirgilKeyPair > result;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generateRecommended();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generateFrom_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  SwigValueWrapper< virgil::crypto::VirgilKeyPair > result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilKeyPair const & reference is null");
    return 0;
  } 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generateFrom((virgil::crypto::VirgilKeyPair const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generateFrom_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  SwigValueWrapper< virgil::crypto::VirgilKeyPair > result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilKeyPair const & reference is null");
    return 0;
  } 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generateFrom((virgil::crypto::VirgilKeyPair const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1generateFrom_1_1SWIG_12(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair *arg1 = 0 ;
  SwigValueWrapper< virgil::crypto::VirgilKeyPair > result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilKeyPair const & reference is null");
    return 0;
  } 
  {
    try {
      result = virgil::crypto::VirgilKeyPair::generateFrom((virgil::crypto::VirgilKeyPair const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = new virgil::crypto::VirgilKeyPair((const virgil::crypto::VirgilKeyPair &)result); 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1isKeyPairMatch_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2, jbyteArray jarg3) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::VirgilKeyPair::isKeyPairMatch((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1isKeyPairMatch_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::VirgilKeyPair::isKeyPairMatch((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1checkPrivateKeyPassword(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::VirgilKeyPair::checkPrivateKeyPassword((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1isPrivateKeyEncrypted(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::VirgilKeyPair::isPrivateKeyEncrypted((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1resetPrivateKeyPassword(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::resetPrivateKeyPassword((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1encryptPrivateKey(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::encryptPrivateKey((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1decryptPrivateKey(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::decryptPrivateKey((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1extractPublicKey(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::extractPublicKey((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1publicKeyToPEM(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::publicKeyToPEM((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1publicKeyToDER(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::publicKeyToDER((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1privateKeyToPEM_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::privateKeyToPEM((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1privateKeyToPEM_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::privateKeyToPEM((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1privateKeyToDER_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::privateKeyToDER((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1privateKeyToDER_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilKeyPair::privateKeyToDER((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilKeyPair_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilKeyPair *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::VirgilKeyPair *)new virgil::crypto::VirgilKeyPair((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1publicKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilKeyPair *arg1 = (virgil::crypto::VirgilKeyPair *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::VirgilKeyPair const *)arg1)->publicKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKeyPair_1privateKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilKeyPair *arg1 = (virgil::crypto::VirgilKeyPair *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::VirgilKeyPair const *)arg1)->privateKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilKeyPair_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilKeyPair *arg1 = 0 ;
  virgil::crypto::VirgilKeyPair *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilKeyPair const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::VirgilKeyPair *)new virgil::crypto::VirgilKeyPair((virgil::crypto::VirgilKeyPair const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilKeyPair **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilKeyPair(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilKeyPair *arg1 = (virgil::crypto::VirgilKeyPair *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilKeyPair **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilAsn1Reader_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *)new virgil::crypto::foundation::asn1::VirgilAsn1Reader();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilAsn1Reader_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *)new virgil::crypto::foundation::asn1::VirgilAsn1Reader((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilAsn1Reader(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Reader_1reset(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->reset((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Reader_1readInteger(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jint jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *) 0 ;
  int result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jarg1; 
  {
    try {
      result = (int)(arg1)->readInteger();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Reader_1readBool(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jarg1; 
  {
    try {
      result = (bool)(arg1)->readBool();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Reader_1readNull(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jarg1; 
  {
    try {
      (arg1)->readNull();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Reader_1readOctetString(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jarg1; 
  {
    try {
      result = (arg1)->readOctetString();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Reader_1readUTF8String(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jarg1; 
  {
    try {
      result = (arg1)->readUTF8String();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Reader_1readData(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jarg1; 
  {
    try {
      result = (arg1)->readData();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Reader_1readContextTag(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jshort jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *) 0 ;
  unsigned char arg2 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jarg1; 
  arg2 = (unsigned char)jarg2; 
  {
    try {
      result = (arg1)->readContextTag(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Reader_1readOID(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jstring jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *) 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jarg1; 
  {
    try {
      result = (arg1)->readOID();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Reader_1readSequence(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jarg1; 
  {
    try {
      result = (arg1)->readSequence();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Reader_1readSet(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Reader *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Reader *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Reader **)&jarg1; 
  {
    try {
      result = (arg1)->readSet();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilAsn1Writer_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *)new virgil::crypto::foundation::asn1::VirgilAsn1Writer();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilAsn1Writer_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  jlong jresult = 0 ;
  size_t arg1 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = (size_t)jarg1; 
  {
    try {
      result = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *)new virgil::crypto::foundation::asn1::VirgilAsn1Writer(arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilAsn1Writer(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1reset_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  {
    try {
      (arg1)->reset();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1reset_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2) {
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  size_t arg2 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  arg2 = (size_t)jarg2; 
  {
    try {
      (arg1)->reset(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1finish(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  {
    try {
      result = (arg1)->finish();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1writeInteger(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jint jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  int arg2 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  arg2 = (int)jarg2; 
  {
    try {
      result = (arg1)->writeInteger(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1writeBool(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jboolean jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  bool arg2 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  arg2 = jarg2 ? true : false; 
  {
    try {
      result = (arg1)->writeBool(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1writeNull(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  {
    try {
      result = (arg1)->writeNull();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1writeOctetString(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->writeOctetString((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1writeUTF8String(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->writeUTF8String((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1writeContextTag(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jshort jarg2, jlong jarg3) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  unsigned char arg2 ;
  size_t arg3 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  arg2 = (unsigned char)jarg2; 
  arg3 = (size_t)jarg3; 
  {
    try {
      result = (arg1)->writeContextTag(arg2,arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1writeData(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->writeData((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1writeOID(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jstring jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  std::string *arg2 = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg2_pstr = (const char *)jenv->GetStringUTFChars(jarg2, 0); 
  if (!arg2_pstr) return 0;
  std::string arg2_str(arg2_pstr);
  arg2 = &arg2_str;
  jenv->ReleaseStringUTFChars(jarg2, arg2_pstr); 
  {
    try {
      result = (arg1)->writeOID((std::string const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1writeSequence(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  size_t arg2 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  arg2 = (size_t)jarg2; 
  {
    try {
      result = (arg1)->writeSequence(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsn1Writer_1writeSet(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::asn1::VirgilAsn1Writer *arg1 = (virgil::crypto::foundation::asn1::VirgilAsn1Writer *) 0 ;
  std::vector< virgil::crypto::VirgilByteArray > *arg2 = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::asn1::VirgilAsn1Writer **)&jarg1; 
  arg2 = *(std::vector< virgil::crypto::VirgilByteArray > **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "std::vector< virgil::crypto::VirgilByteArray > const & reference is null");
    return 0;
  } 
  {
    try {
      result = (arg1)->writeSet((std::vector< virgil::crypto::VirgilByteArray > const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSKeyTransRecipient_1recipientIdentifier_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if (arg1) (arg1)->recipientIdentifier = *arg2;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSKeyTransRecipient_1recipientIdentifier_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient **)&jarg1; 
  result = (virgil::crypto::VirgilByteArray *) & ((arg1)->recipientIdentifier);
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSKeyTransRecipient_1keyEncryptionAlgorithm_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if (arg1) (arg1)->keyEncryptionAlgorithm = *arg2;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSKeyTransRecipient_1keyEncryptionAlgorithm_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient **)&jarg1; 
  result = (virgil::crypto::VirgilByteArray *) & ((arg1)->keyEncryptionAlgorithm);
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSKeyTransRecipient_1encryptedKey_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if (arg1) (arg1)->encryptedKey = *arg2;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSKeyTransRecipient_1encryptedKey_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient **)&jarg1; 
  result = (virgil::crypto::VirgilByteArray *) & ((arg1)->encryptedKey);
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCMSKeyTransRecipient_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *)new virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCMSKeyTransRecipient_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *arg1 = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *)new virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient((virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilCMSKeyTransRecipient(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSPasswordRecipient_1keyDerivationAlgorithm_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if (arg1) (arg1)->keyDerivationAlgorithm = *arg2;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSPasswordRecipient_1keyDerivationAlgorithm_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient **)&jarg1; 
  result = (virgil::crypto::VirgilByteArray *) & ((arg1)->keyDerivationAlgorithm);
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSPasswordRecipient_1keyEncryptionAlgorithm_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if (arg1) (arg1)->keyEncryptionAlgorithm = *arg2;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSPasswordRecipient_1keyEncryptionAlgorithm_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient **)&jarg1; 
  result = (virgil::crypto::VirgilByteArray *) & ((arg1)->keyEncryptionAlgorithm);
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSPasswordRecipient_1encryptedKey_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if (arg1) (arg1)->encryptedKey = *arg2;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSPasswordRecipient_1encryptedKey_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient **)&jarg1; 
  result = (virgil::crypto::VirgilByteArray *) & ((arg1)->encryptedKey);
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCMSPasswordRecipient_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *)new virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCMSPasswordRecipient_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *arg1 = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *)new virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient((virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilCMSPasswordRecipient(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *arg1 = (virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSEncryptedContent_1contentEncryptionAlgorithm_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *arg1 = (virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEncryptedContent **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if (arg1) (arg1)->contentEncryptionAlgorithm = *arg2;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSEncryptedContent_1contentEncryptionAlgorithm_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *arg1 = (virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEncryptedContent **)&jarg1; 
  result = (virgil::crypto::VirgilByteArray *) & ((arg1)->contentEncryptionAlgorithm);
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSEncryptedContent_1encryptedContent_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *arg1 = (virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEncryptedContent **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if (arg1) (arg1)->encryptedContent = *arg2;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSEncryptedContent_1encryptedContent_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *arg1 = (virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEncryptedContent **)&jarg1; 
  result = (virgil::crypto::VirgilByteArray *) & ((arg1)->encryptedContent);
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCMSEncryptedContent_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *)new virgil::crypto::foundation::cms::VirgilCMSEncryptedContent();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::cms::VirgilCMSEncryptedContent **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCMSEncryptedContent_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *arg1 = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEncryptedContent **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::cms::VirgilCMSEncryptedContent const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *)new virgil::crypto::foundation::cms::VirgilCMSEncryptedContent((virgil::crypto::foundation::cms::VirgilCMSEncryptedContent const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::cms::VirgilCMSEncryptedContent **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilCMSEncryptedContent(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *arg1 = (virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEncryptedContent **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSEnvelopedData_1keyTransRecipients_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2) {
  virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *arg1 = (virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *) 0 ;
  std::vector< virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient > *arg2 = (std::vector< virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient > *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEnvelopedData **)&jarg1; 
  arg2 = *(std::vector< virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient > **)&jarg2; 
  if (arg1) (arg1)->keyTransRecipients = *arg2;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSEnvelopedData_1keyTransRecipients_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *arg1 = (virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *) 0 ;
  std::vector< virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient > *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEnvelopedData **)&jarg1; 
  result = (std::vector< virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient > *)& ((arg1)->keyTransRecipients);
  *(std::vector< virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient > **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSEnvelopedData_1passwordRecipients_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2) {
  virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *arg1 = (virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *) 0 ;
  std::vector< virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient > *arg2 = (std::vector< virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient > *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEnvelopedData **)&jarg1; 
  arg2 = *(std::vector< virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient > **)&jarg2; 
  if (arg1) (arg1)->passwordRecipients = *arg2;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSEnvelopedData_1passwordRecipients_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *arg1 = (virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *) 0 ;
  std::vector< virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient > *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEnvelopedData **)&jarg1; 
  result = (std::vector< virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient > *)& ((arg1)->passwordRecipients);
  *(std::vector< virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient > **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSEnvelopedData_1encryptedContent_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_) {
  virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *arg1 = (virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *) 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *arg2 = (virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEnvelopedData **)&jarg1; 
  arg2 = *(virgil::crypto::foundation::cms::VirgilCMSEncryptedContent **)&jarg2; 
  if (arg1) (arg1)->encryptedContent = *arg2;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSEnvelopedData_1encryptedContent_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *arg1 = (virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *) 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEnvelopedData **)&jarg1; 
  result = (virgil::crypto::foundation::cms::VirgilCMSEncryptedContent *)& ((arg1)->encryptedContent);
  *(virgil::crypto::foundation::cms::VirgilCMSEncryptedContent **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCMSEnvelopedData_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *)new virgil::crypto::foundation::cms::VirgilCMSEnvelopedData();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::cms::VirgilCMSEnvelopedData **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCMSEnvelopedData_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *arg1 = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEnvelopedData **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::cms::VirgilCMSEnvelopedData const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *)new virgil::crypto::foundation::cms::VirgilCMSEnvelopedData((virgil::crypto::foundation::cms::VirgilCMSEnvelopedData const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::cms::VirgilCMSEnvelopedData **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilCMSEnvelopedData(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *arg1 = (virgil::crypto::foundation::cms::VirgilCMSEnvelopedData *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSEnvelopedData **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSContent_1Type_1Data_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContent::Type result;
  
  (void)jenv;
  (void)jcls;
  result = (virgil::crypto::foundation::cms::VirgilCMSContent::Type)virgil::crypto::foundation::cms::VirgilCMSContent::Type::Data;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSContent_1contentType_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jint jarg2) {
  virgil::crypto::foundation::cms::VirgilCMSContent *arg1 = (virgil::crypto::foundation::cms::VirgilCMSContent *) 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContent::Type arg2 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSContent **)&jarg1; 
  arg2 = (virgil::crypto::foundation::cms::VirgilCMSContent::Type)jarg2; 
  if (arg1) (arg1)->contentType = arg2;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSContent_1contentType_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jint jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContent *arg1 = (virgil::crypto::foundation::cms::VirgilCMSContent *) 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContent::Type result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSContent **)&jarg1; 
  result = (virgil::crypto::foundation::cms::VirgilCMSContent::Type) ((arg1)->contentType);
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSContent_1content_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::cms::VirgilCMSContent *arg1 = (virgil::crypto::foundation::cms::VirgilCMSContent *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSContent **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if (arg1) (arg1)->content = *arg2;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSContent_1content_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContent *arg1 = (virgil::crypto::foundation::cms::VirgilCMSContent *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSContent **)&jarg1; 
  result = (virgil::crypto::VirgilByteArray *) & ((arg1)->content);
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCMSContent_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContent *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::cms::VirgilCMSContent *)new virgil::crypto::foundation::cms::VirgilCMSContent();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::cms::VirgilCMSContent **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCMSContent_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContent *arg1 = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContent *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSContent **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::cms::VirgilCMSContent const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::foundation::cms::VirgilCMSContent *)new virgil::crypto::foundation::cms::VirgilCMSContent((virgil::crypto::foundation::cms::VirgilCMSContent const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::cms::VirgilCMSContent **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilCMSContent(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::cms::VirgilCMSContent *arg1 = (virgil::crypto::foundation::cms::VirgilCMSContent *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSContent **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSContentInfo_1cmsContent_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_) {
  virgil::crypto::foundation::cms::VirgilCMSContentInfo *arg1 = (virgil::crypto::foundation::cms::VirgilCMSContentInfo *) 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContent *arg2 = (virgil::crypto::foundation::cms::VirgilCMSContent *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSContentInfo **)&jarg1; 
  arg2 = *(virgil::crypto::foundation::cms::VirgilCMSContent **)&jarg2; 
  if (arg1) (arg1)->cmsContent = *arg2;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSContentInfo_1cmsContent_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContentInfo *arg1 = (virgil::crypto::foundation::cms::VirgilCMSContentInfo *) 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContent *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSContentInfo **)&jarg1; 
  result = (virgil::crypto::foundation::cms::VirgilCMSContent *)& ((arg1)->cmsContent);
  *(virgil::crypto::foundation::cms::VirgilCMSContent **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSContentInfo_1customParams_1set(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_) {
  virgil::crypto::foundation::cms::VirgilCMSContentInfo *arg1 = (virgil::crypto::foundation::cms::VirgilCMSContentInfo *) 0 ;
  virgil::crypto::VirgilCustomParams *arg2 = (virgil::crypto::VirgilCustomParams *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSContentInfo **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilCustomParams **)&jarg2; 
  if (arg1) (arg1)->customParams = *arg2;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSContentInfo_1customParams_1get(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContentInfo *arg1 = (virgil::crypto::foundation::cms::VirgilCMSContentInfo *) 0 ;
  virgil::crypto::VirgilCustomParams *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSContentInfo **)&jarg1; 
  result = (virgil::crypto::VirgilCustomParams *)& ((arg1)->customParams);
  *(virgil::crypto::VirgilCustomParams **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSContentInfo_1defineSize(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::foundation::cms::VirgilCMSContentInfo::defineSize((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCMSContentInfo_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContentInfo *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::cms::VirgilCMSContentInfo *)new virgil::crypto::foundation::cms::VirgilCMSContentInfo();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::cms::VirgilCMSContentInfo **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCMSContentInfo_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContentInfo *arg1 = 0 ;
  virgil::crypto::foundation::cms::VirgilCMSContentInfo *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSContentInfo **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::cms::VirgilCMSContentInfo const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::foundation::cms::VirgilCMSContentInfo *)new virgil::crypto::foundation::cms::VirgilCMSContentInfo((virgil::crypto::foundation::cms::VirgilCMSContentInfo const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::cms::VirgilCMSContentInfo **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilCMSContentInfo(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::cms::VirgilCMSContentInfo *arg1 = (virgil::crypto::foundation::cms::VirgilCMSContentInfo *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::cms::VirgilCMSContentInfo **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilHash_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::VirgilHash *)new virgil::crypto::foundation::VirgilHash();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilHash **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilHash_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jint jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash::Algorithm arg1 ;
  virgil::crypto::foundation::VirgilHash *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::foundation::VirgilHash::Algorithm)jarg1; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilHash *)new virgil::crypto::foundation::VirgilHash(arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilHash **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilHash_1_1SWIG_12(JNIEnv *jenv, jclass jcls, jstring jarg1) {
  jlong jresult = 0 ;
  std::string *arg1 = 0 ;
  virgil::crypto::foundation::VirgilHash *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg1_pstr = (const char *)jenv->GetStringUTFChars(jarg1, 0); 
  if (!arg1_pstr) return 0;
  std::string arg1_str(arg1_pstr);
  arg1 = &arg1_str;
  jenv->ReleaseStringUTFChars(jarg1, arg1_pstr); 
  {
    try {
      result = (virgil::crypto::foundation::VirgilHash *)new virgil::crypto::foundation::VirgilHash((std::string const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilHash **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1name(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jstring jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilHash const *)arg1)->name();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1algorithm(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jint jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::foundation::VirgilHash::Algorithm result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilHash::Algorithm)((virgil::crypto::foundation::VirgilHash const *)arg1)->algorithm();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1type(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jint jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  int result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      result = (int)((virgil::crypto::foundation::VirgilHash const *)arg1)->type();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1size(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilHash const *)arg1)->size();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1hash(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::foundation::VirgilHash const *)arg1)->hash((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1start(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      (arg1)->start();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1update(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->update((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1finish(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      result = (arg1)->finish();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1hmac(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::foundation::VirgilHash const *)arg1)->hmac((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1hmacStart(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->hmacStart((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1hmacReset(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      (arg1)->hmacReset();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1hmacUpdate(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->hmacUpdate((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1hmacFinish(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      result = (arg1)->hmacFinish();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilHash(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilHash *arg1 = (virgil::crypto::foundation::VirgilHash *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilHash_1_1SWIG_13(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash *arg1 = 0 ;
  virgil::crypto::foundation::VirgilHash *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHash **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::VirgilHash const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::foundation::VirgilHash *)new virgil::crypto::foundation::VirgilHash((virgil::crypto::foundation::VirgilHash const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilHash **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilKDF_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilKDF *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::VirgilKDF *)new virgil::crypto::foundation::VirgilKDF();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilKDF **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilKDF_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jint jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilKDF::Algorithm arg1 ;
  virgil::crypto::foundation::VirgilKDF *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::foundation::VirgilKDF::Algorithm)jarg1; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilKDF *)new virgil::crypto::foundation::VirgilKDF(arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilKDF **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilKDF_1_1SWIG_12(JNIEnv *jenv, jclass jcls, jstring jarg1) {
  jlong jresult = 0 ;
  std::string *arg1 = 0 ;
  virgil::crypto::foundation::VirgilKDF *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg1_pstr = (const char *)jenv->GetStringUTFChars(jarg1, 0); 
  if (!arg1_pstr) return 0;
  std::string arg1_str(arg1_pstr);
  arg1 = &arg1_str;
  jenv->ReleaseStringUTFChars(jarg1, arg1_pstr); 
  {
    try {
      result = (virgil::crypto::foundation::VirgilKDF *)new virgil::crypto::foundation::VirgilKDF((std::string const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilKDF **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKDF_1name(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jstring jresult = 0 ;
  virgil::crypto::foundation::VirgilKDF *arg1 = (virgil::crypto::foundation::VirgilKDF *) 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilKDF **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilKDF const *)arg1)->name();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKDF_1derive(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jlong jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilKDF *arg1 = (virgil::crypto::foundation::VirgilKDF *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  size_t arg3 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilKDF **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  arg3 = (size_t)jarg3; 
  {
    try {
      result = (arg1)->derive((virgil::crypto::VirgilByteArray const &)*arg2,arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilKDF(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilKDF *arg1 = (virgil::crypto::foundation::VirgilKDF *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilKDF **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1Padding_1PKCS7_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher::Padding result;
  
  (void)jenv;
  (void)jcls;
  result = (virgil::crypto::foundation::VirgilSymmetricCipher::Padding)virgil::crypto::foundation::VirgilSymmetricCipher::Padding::PKCS7;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilSymmetricCipher_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::VirgilSymmetricCipher *)new virgil::crypto::foundation::VirgilSymmetricCipher();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilSymmetricCipher_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jint jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher::Algorithm arg1 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher::Algorithm)jarg1; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilSymmetricCipher *)new virgil::crypto::foundation::VirgilSymmetricCipher(arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilSymmetricCipher_1_1SWIG_12(JNIEnv *jenv, jclass jcls, jstring jarg1) {
  jlong jresult = 0 ;
  std::string *arg1 = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg1_pstr = (const char *)jenv->GetStringUTFChars(jarg1, 0); 
  if (!arg1_pstr) return 0;
  std::string arg1_str(arg1_pstr);
  arg1 = &arg1_str;
  jenv->ReleaseStringUTFChars(jarg1, arg1_pstr); 
  {
    try {
      result = (virgil::crypto::foundation::VirgilSymmetricCipher *)new virgil::crypto::foundation::VirgilSymmetricCipher((std::string const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1name(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jstring jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilSymmetricCipher const *)arg1)->name();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1blockSize(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilSymmetricCipher const *)arg1)->blockSize();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1ivSize(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilSymmetricCipher const *)arg1)->ivSize();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1keySize(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilSymmetricCipher const *)arg1)->keySize();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1keyLength(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilSymmetricCipher const *)arg1)->keyLength();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1authTagLength(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilSymmetricCipher const *)arg1)->authTagLength();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1isEncryptionMode(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      result = (bool)((virgil::crypto::foundation::VirgilSymmetricCipher const *)arg1)->isEncryptionMode();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1isDecryptionMode(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      result = (bool)((virgil::crypto::foundation::VirgilSymmetricCipher const *)arg1)->isDecryptionMode();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1isAuthMode(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      result = (bool)((virgil::crypto::foundation::VirgilSymmetricCipher const *)arg1)->isAuthMode();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1isSupportPadding(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      result = (bool)((virgil::crypto::foundation::VirgilSymmetricCipher const *)arg1)->isSupportPadding();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1iv(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilSymmetricCipher const *)arg1)->iv();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1setEncryptionKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->setEncryptionKey((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1setDecryptionKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->setDecryptionKey((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1setPadding(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jint jarg2) {
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher::Padding arg2 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  arg2 = (virgil::crypto::foundation::VirgilSymmetricCipher::Padding)jarg2; 
  {
    try {
      (arg1)->setPadding(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1setIV(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->setIV((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1setAuthData(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->setAuthData((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1reset(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      (arg1)->reset();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1clear(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      (arg1)->clear();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1crypt(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->crypt((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1update(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->update((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1finish(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      result = (arg1)->finish();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilSymmetricCipher(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilSymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilSymmetricCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilAsymmetricCipher(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::VirgilAsymmetricCipher *)new virgil::crypto::foundation::VirgilAsymmetricCipher();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1keySize(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->keySize();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1keyLength(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->keyLength();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1isKeyPairMatch_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2, jbyteArray jarg3) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::foundation::VirgilAsymmetricCipher::isKeyPairMatch((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1isKeyPairMatch_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::foundation::VirgilAsymmetricCipher::isKeyPairMatch((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1isPublicKeyValid(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::foundation::VirgilAsymmetricCipher::isPublicKeyValid((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1checkPublicKey(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return ;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      virgil::crypto::foundation::VirgilAsymmetricCipher::checkPublicKey((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1checkPrivateKeyPassword(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::foundation::VirgilAsymmetricCipher::checkPrivateKeyPassword((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1isPrivateKeyEncrypted(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = (bool)virgil::crypto::foundation::VirgilAsymmetricCipher::isPrivateKeyEncrypted((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1setPrivateKey_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      (arg1)->setPrivateKey((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1setPrivateKey_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->setPrivateKey((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1setPublicKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->setPublicKey((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1genKeyPair(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jint jarg2) {
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilKeyPair::Type arg2 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  arg2 = (virgil::crypto::VirgilKeyPair::Type)jarg2; 
  {
    try {
      (arg1)->genKeyPair(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1genKeyPairFrom(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_) {
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  arg2 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::VirgilAsymmetricCipher const & reference is null");
    return ;
  } 
  {
    try {
      (arg1)->genKeyPairFrom((virgil::crypto::foundation::VirgilAsymmetricCipher const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1computeShared(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::VirgilAsymmetricCipher const & reference is null");
    return 0;
  } 
  arg2 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::VirgilAsymmetricCipher const & reference is null");
    return 0;
  } 
  {
    try {
      result = virgil::crypto::foundation::VirgilAsymmetricCipher::computeShared((virgil::crypto::foundation::VirgilAsymmetricCipher const &)*arg1,(virgil::crypto::foundation::VirgilAsymmetricCipher const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1exportPrivateKeyToDER_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->exportPrivateKeyToDER((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1exportPrivateKeyToDER_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->exportPrivateKeyToDER();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1exportPublicKeyToDER(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->exportPublicKeyToDER();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1exportPrivateKeyToPEM_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->exportPrivateKeyToPEM((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1exportPrivateKeyToPEM_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->exportPrivateKeyToPEM();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1exportPublicKeyToPEM(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->exportPublicKeyToPEM();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1getKeyType(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jint jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilKeyPair::Type result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilKeyPair::Type)((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->getKeyType();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1setKeyType(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jint jarg2) {
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilKeyPair::Type arg2 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  arg2 = (virgil::crypto::VirgilKeyPair::Type)jarg2; 
  {
    try {
      (arg1)->setKeyType(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1getPublicKeyBits(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->getPublicKeyBits();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1setPublicKeyBits(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->setPublicKeyBits((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1encrypt(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->encrypt((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1decrypt(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->decrypt((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1sign(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jint jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  int arg3 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  arg3 = (int)jarg3; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->sign((virgil::crypto::VirgilByteArray const &)*arg2,arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1verify(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jint jarg4) {
  jboolean jresult = 0 ;
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  int arg4 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  arg4 = (int)jarg4; 
  {
    try {
      result = (bool)((virgil::crypto::foundation::VirgilAsymmetricCipher const *)arg1)->verify((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilAsymmetricCipher(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilAsymmetricCipher *arg1 = (virgil::crypto::foundation::VirgilAsymmetricCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBE_1kIterationCountMin_1get(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  result = virgil::crypto::foundation::VirgilPBE::kIterationCountMin;
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPBE_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilPBE *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::VirgilPBE *)new virgil::crypto::foundation::VirgilPBE();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilPBE **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPBE_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jint jarg1, jbyteArray jarg2, jlong jarg3) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilPBE::Algorithm arg1 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  size_t arg3 ;
  virgil::crypto::foundation::VirgilPBE *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::foundation::VirgilPBE::Algorithm)jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  arg3 = (size_t)jarg3; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilPBE *)new virgil::crypto::foundation::VirgilPBE(arg1,(virgil::crypto::VirgilByteArray const &)*arg2,arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilPBE **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPBE_1_1SWIG_12(JNIEnv *jenv, jclass jcls, jint jarg1, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilPBE::Algorithm arg1 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::foundation::VirgilPBE *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::foundation::VirgilPBE::Algorithm)jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::foundation::VirgilPBE *)new virgil::crypto::foundation::VirgilPBE(arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilPBE **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBE_1encrypt(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilPBE *arg1 = (virgil::crypto::foundation::VirgilPBE *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBE **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::foundation::VirgilPBE const *)arg1)->encrypt((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBE_1decrypt(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilPBE *arg1 = (virgil::crypto::foundation::VirgilPBE *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBE **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::foundation::VirgilPBE const *)arg1)->decrypt((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilPBE(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilPBE *arg1 = (virgil::crypto::foundation::VirgilPBE *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilPBE **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilHKDF(JNIEnv *jenv, jclass jcls, jint jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash::Algorithm arg1 ;
  virgil::crypto::foundation::VirgilHKDF *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::foundation::VirgilHash::Algorithm)jarg1; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilHKDF *)new virgil::crypto::foundation::VirgilHKDF(arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilHKDF **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHKDF_1derive(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4, jlong jarg5) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilHKDF *arg1 = (virgil::crypto::foundation::VirgilHKDF *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  size_t arg5 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilHKDF **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  arg5 = (size_t)jarg5; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilHKDF const *)arg1)->derive((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4,arg5);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilHKDF(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilHKDF *arg1 = (virgil::crypto::foundation::VirgilHKDF *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilHKDF **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilBase64_1encode(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jstring jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::foundation::VirgilBase64::encode((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilBase64_1decode(JNIEnv *jenv, jclass jcls, jstring jarg1) {
  jbyteArray jresult = 0 ;
  std::string *arg1 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg1_pstr = (const char *)jenv->GetStringUTFChars(jarg1, 0); 
  if (!arg1_pstr) return 0;
  std::string arg1_str(arg1_pstr);
  arg1 = &arg1_str;
  jenv->ReleaseStringUTFChars(jarg1, arg1_pstr); 
  {
    try {
      result = virgil::crypto::foundation::VirgilBase64::decode((std::string const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilBase64(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilBase64 *arg1 = (virgil::crypto::foundation::VirgilBase64 *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilBase64 **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1kIterationCount_1Default_1get(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  unsigned int result;
  
  (void)jenv;
  (void)jcls;
  result = (unsigned int)virgil::crypto::foundation::VirgilPBKDF::kIterationCount_Default;
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPBKDF_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::foundation::VirgilPBKDF *)new virgil::crypto::foundation::VirgilPBKDF();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilPBKDF **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPBKDF_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jlong jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  unsigned int arg2 ;
  virgil::crypto::foundation::VirgilPBKDF *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  arg2 = (unsigned int)jarg2; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilPBKDF *)new virgil::crypto::foundation::VirgilPBKDF((virgil::crypto::VirgilByteArray const &)*arg1,arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilPBKDF **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPBKDF_1_1SWIG_12(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::foundation::VirgilPBKDF *)new virgil::crypto::foundation::VirgilPBKDF((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilPBKDF **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1getSalt(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::foundation::VirgilPBKDF const *)arg1)->getSalt();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1getIterationCount(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  unsigned int result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      result = (unsigned int)((virgil::crypto::foundation::VirgilPBKDF const *)arg1)->getIterationCount();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1setAlgorithm(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jint jarg2) {
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::foundation::VirgilPBKDF::Algorithm arg2 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  arg2 = (virgil::crypto::foundation::VirgilPBKDF::Algorithm)jarg2; 
  {
    try {
      (arg1)->setAlgorithm(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1getAlgorithm(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jint jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::foundation::VirgilPBKDF::Algorithm result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilPBKDF::Algorithm)((virgil::crypto::foundation::VirgilPBKDF const *)arg1)->getAlgorithm();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1setHashAlgorithm(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jint jarg2) {
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::foundation::VirgilHash::Algorithm arg2 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  arg2 = (virgil::crypto::foundation::VirgilHash::Algorithm)jarg2; 
  {
    try {
      (arg1)->setHashAlgorithm(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1getHashAlgorithm(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jint jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::foundation::VirgilHash::Algorithm result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilHash::Algorithm)((virgil::crypto::foundation::VirgilPBKDF const *)arg1)->getHashAlgorithm();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1enableRecommendationsCheck(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      (arg1)->enableRecommendationsCheck();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1disableRecommendationsCheck(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      (arg1)->disableRecommendationsCheck();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1derive_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jlong jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  size_t arg3 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  arg3 = (size_t)jarg3; 
  {
    try {
      result = (arg1)->derive((virgil::crypto::VirgilByteArray const &)*arg2,arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1derive_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->derive((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilPBKDF(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilPBKDF *arg1 = (virgil::crypto::foundation::VirgilPBKDF *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilRandom_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jstring jarg1) {
  jlong jresult = 0 ;
  std::string *arg1 = 0 ;
  virgil::crypto::foundation::VirgilRandom *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg1_pstr = (const char *)jenv->GetStringUTFChars(jarg1, 0); 
  if (!arg1_pstr) return 0;
  std::string arg1_str(arg1_pstr);
  arg1 = &arg1_str;
  jenv->ReleaseStringUTFChars(jarg1, arg1_pstr); 
  {
    try {
      result = (virgil::crypto::foundation::VirgilRandom *)new virgil::crypto::foundation::VirgilRandom((std::string const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilRandom **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilRandom_1randomize_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::foundation::VirgilRandom *arg1 = (virgil::crypto::foundation::VirgilRandom *) 0 ;
  size_t arg2 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilRandom **)&jarg1; 
  arg2 = (size_t)jarg2; 
  {
    try {
      result = (arg1)->randomize(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilRandom_1randomize_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilRandom *arg1 = (virgil::crypto::foundation::VirgilRandom *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilRandom **)&jarg1; 
  {
    try {
      result = (arg1)->randomize();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilRandom_1randomize_1_1SWIG_12(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jlong jarg3) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilRandom *arg1 = (virgil::crypto::foundation::VirgilRandom *) 0 ;
  size_t arg2 ;
  size_t arg3 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilRandom **)&jarg1; 
  arg2 = (size_t)jarg2; 
  arg3 = (size_t)jarg3; 
  {
    try {
      result = (arg1)->randomize(arg2,arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilRandom(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::foundation::VirgilRandom *arg1 = (virgil::crypto::foundation::VirgilRandom *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::foundation::VirgilRandom **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilRandom_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilRandom *arg1 = 0 ;
  virgil::crypto::foundation::VirgilRandom *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::foundation::VirgilRandom **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::foundation::VirgilRandom const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::foundation::VirgilRandom *)new virgil::crypto::foundation::VirgilRandom((virgil::crypto::foundation::VirgilRandom const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::foundation::VirgilRandom **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1isEmpty(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  {
    try {
      result = (bool)((virgil::crypto::VirgilCustomParams const *)arg1)->isEmpty();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1setInteger(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jint jarg3) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  int arg3 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  arg3 = (int)jarg3; 
  {
    try {
      (arg1)->setInteger((virgil::crypto::VirgilByteArray const &)*arg2,arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1getInteger(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jint jresult = 0 ;
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  int result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (int)((virgil::crypto::VirgilCustomParams const *)arg1)->getInteger((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1removeInteger(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->removeInteger((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1setString(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      (arg1)->setString((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1getString(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::VirgilCustomParams const *)arg1)->getString((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1removeString(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->removeString((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1setData(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      (arg1)->setData((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1getData(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = ((virgil::crypto::VirgilCustomParams const *)arg1)->getData((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1removeData(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->removeData((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1clear(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  {
    try {
      (arg1)->clear();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCustomParams_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilCustomParams *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilCustomParams *)new virgil::crypto::VirgilCustomParams();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilCustomParams **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCustomParams_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilCustomParams *arg1 = 0 ;
  virgil::crypto::VirgilCustomParams *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilCustomParams const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::VirgilCustomParams *)new virgil::crypto::VirgilCustomParams((virgil::crypto::VirgilCustomParams const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilCustomParams **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilCustomParams(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilCustomParams *arg1 = (virgil::crypto::VirgilCustomParams *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilCustomParams **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCipherBase(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilCipherBase *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilCipherBase *)new virgil::crypto::VirgilCipherBase();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilCipherBase **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1addKeyRecipient(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      (arg1)->addKeyRecipient((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1removeKeyRecipient(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->removeKeyRecipient((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1keyRecipientExists(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (bool)((virgil::crypto::VirgilCipherBase const *)arg1)->keyRecipientExists((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1addPasswordRecipient(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->addPasswordRecipient((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1removePasswordRecipient(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->removePasswordRecipient((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1passwordRecipientExists(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (bool)((virgil::crypto::VirgilCipherBase const *)arg1)->passwordRecipientExists((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1removeAllRecipients(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  {
    try {
      (arg1)->removeAllRecipients();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1getContentInfo(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::VirgilCipherBase const *)arg1)->getContentInfo();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1setContentInfo(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->setContentInfo((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1defineContentInfoSize(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilCipherBase::defineContentInfoSize((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1customParams_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  virgil::crypto::VirgilCustomParams *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilCustomParams *) &(arg1)->customParams();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilCustomParams **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1computeShared_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilCipherBase::computeShared((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipherBase_1computeShared_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilCipherBase::computeShared((virgil::crypto::VirgilByteArray const &)*arg1,(virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilCipherBase(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilCipherBase *arg1 = (virgil::crypto::VirgilCipherBase *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilCipherBase **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipher_1encrypt_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jboolean jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCipher *arg1 = (virgil::crypto::VirgilCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  bool arg3 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  arg3 = jarg3 ? true : false; 
  {
    try {
      result = (arg1)->encrypt((virgil::crypto::VirgilByteArray const &)*arg2,arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipher_1encrypt_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCipher *arg1 = (virgil::crypto::VirgilCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->encrypt((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipher_1decryptWithKey_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4, jbyteArray jarg5) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCipher *arg1 = (virgil::crypto::VirgilCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray *arg5 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  if(!jarg5) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg5_pdata = (jbyte *)jenv->GetByteArrayElements(jarg5, 0);
  size_t arg5_size = (size_t)jenv->GetArrayLength(jarg5);
  if (!arg5_pdata) return 0;
  virgil::crypto::VirgilByteArray arg5_data(arg5_pdata, arg5_pdata + arg5_size);
  arg5 = &arg5_data;
  jenv->ReleaseByteArrayElements(jarg5, arg5_pdata, 0);
  
  {
    try {
      result = (arg1)->decryptWithKey((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4,(virgil::crypto::VirgilByteArray const &)*arg5);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipher_1decryptWithKey_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCipher *arg1 = (virgil::crypto::VirgilCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (arg1)->decryptWithKey((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipher_1decryptWithPassword(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilCipher *arg1 = (virgil::crypto::VirgilCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->decryptWithPassword((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilCipher(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilCipher *)new virgil::crypto::VirgilCipher();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilCipher(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilCipher *arg1 = (virgil::crypto::VirgilCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilCipher **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1kPreferredChunkSize_1get(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  result = virgil::crypto::VirgilChunkCipher::kPreferredChunkSize;
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1encrypt_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jboolean jarg4, jlong jarg5) {
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  bool arg4 ;
  size_t arg5 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  arg4 = jarg4 ? true : false; 
  arg5 = (size_t)jarg5; 
  {
    try {
      (arg1)->encrypt(*arg2,*arg3,arg4,arg5);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1encrypt_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jboolean jarg4) {
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  bool arg4 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  arg4 = jarg4 ? true : false; 
  {
    try {
      (arg1)->encrypt(*arg2,*arg3,arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1encrypt_1_1SWIG_12(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_) {
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  {
    try {
      (arg1)->encrypt(*arg2,*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1decryptWithKey_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jbyteArray jarg4, jbyteArray jarg5, jbyteArray jarg6) {
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray *arg5 = 0 ;
  virgil::crypto::VirgilByteArray *arg6 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  if(!jarg5) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg5_pdata = (jbyte *)jenv->GetByteArrayElements(jarg5, 0);
  size_t arg5_size = (size_t)jenv->GetArrayLength(jarg5);
  if (!arg5_pdata) return ;
  virgil::crypto::VirgilByteArray arg5_data(arg5_pdata, arg5_pdata + arg5_size);
  arg5 = &arg5_data;
  jenv->ReleaseByteArrayElements(jarg5, arg5_pdata, 0);
  
  if(!jarg6) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg6_pdata = (jbyte *)jenv->GetByteArrayElements(jarg6, 0);
  size_t arg6_size = (size_t)jenv->GetArrayLength(jarg6);
  if (!arg6_pdata) return ;
  virgil::crypto::VirgilByteArray arg6_data(arg6_pdata, arg6_pdata + arg6_size);
  arg6 = &arg6_data;
  jenv->ReleaseByteArrayElements(jarg6, arg6_pdata, 0);
  
  {
    try {
      (arg1)->decryptWithKey(*arg2,*arg3,(virgil::crypto::VirgilByteArray const &)*arg4,(virgil::crypto::VirgilByteArray const &)*arg5,(virgil::crypto::VirgilByteArray const &)*arg6);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1decryptWithKey_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jbyteArray jarg4, jbyteArray jarg5) {
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray *arg5 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  if(!jarg5) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg5_pdata = (jbyte *)jenv->GetByteArrayElements(jarg5, 0);
  size_t arg5_size = (size_t)jenv->GetArrayLength(jarg5);
  if (!arg5_pdata) return ;
  virgil::crypto::VirgilByteArray arg5_data(arg5_pdata, arg5_pdata + arg5_size);
  arg5 = &arg5_data;
  jenv->ReleaseByteArrayElements(jarg5, arg5_pdata, 0);
  
  {
    try {
      (arg1)->decryptWithKey(*arg2,*arg3,(virgil::crypto::VirgilByteArray const &)*arg4,(virgil::crypto::VirgilByteArray const &)*arg5);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1decryptWithPassword(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jbyteArray jarg4) {
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      (arg1)->decryptWithPassword(*arg2,*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilChunkCipher(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilChunkCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilChunkCipher *)new virgil::crypto::VirgilChunkCipher();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilChunkCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilChunkCipher(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilChunkCipher *arg1 = (virgil::crypto::VirgilChunkCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilChunkCipher **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilSignerBase_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jint jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash::Algorithm arg1 ;
  virgil::crypto::VirgilSignerBase *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::foundation::VirgilHash::Algorithm)jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilSignerBase *)new virgil::crypto::VirgilSignerBase(arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilSignerBase **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilSignerBase_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilSignerBase *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilSignerBase *)new virgil::crypto::VirgilSignerBase();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilSignerBase **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSignerBase_1getHashAlgorithm(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jint jresult = 0 ;
  virgil::crypto::VirgilSignerBase *arg1 = (virgil::crypto::VirgilSignerBase *) 0 ;
  virgil::crypto::foundation::VirgilHash::Algorithm result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilSignerBase **)&jarg1; 
  {
    try {
      result = (virgil::crypto::foundation::VirgilHash::Algorithm)((virgil::crypto::VirgilSignerBase const *)arg1)->getHashAlgorithm();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSignerBase_1signHash_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilSignerBase *arg1 = (virgil::crypto::VirgilSignerBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilSignerBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (arg1)->signHash((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSignerBase_1signHash_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilSignerBase *arg1 = (virgil::crypto::VirgilSignerBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilSignerBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->signHash((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSignerBase_1verifyHash(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilSignerBase *arg1 = (virgil::crypto::VirgilSignerBase *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilSignerBase **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (bool)(arg1)->verifyHash((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilSignerBase(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilSignerBase *arg1 = (virgil::crypto::VirgilSignerBase *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilSignerBase **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilSigner_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jint jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash::Algorithm arg1 ;
  virgil::crypto::VirgilSigner *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::foundation::VirgilHash::Algorithm)jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilSigner *)new virgil::crypto::VirgilSigner(arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilSigner **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilSigner_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilSigner *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilSigner *)new virgil::crypto::VirgilSigner();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilSigner **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSigner_1sign_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilSigner *arg1 = (virgil::crypto::VirgilSigner *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilSigner **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (arg1)->sign((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSigner_1sign_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilSigner *arg1 = (virgil::crypto::VirgilSigner *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilSigner **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->sign((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSigner_1verify(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilSigner *arg1 = (virgil::crypto::VirgilSigner *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilSigner **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (bool)(arg1)->verify((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilSigner(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilSigner *arg1 = (virgil::crypto::VirgilSigner *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilSigner **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilStreamSigner_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jint jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::foundation::VirgilHash::Algorithm arg1 ;
  virgil::crypto::VirgilStreamSigner *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = (virgil::crypto::foundation::VirgilHash::Algorithm)jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilStreamSigner *)new virgil::crypto::VirgilStreamSigner(arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilStreamSigner **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilStreamSigner_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilStreamSigner *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilStreamSigner *)new virgil::crypto::VirgilStreamSigner();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilStreamSigner **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamSigner_1sign_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jbyteArray jarg3, jbyteArray jarg4) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilStreamSigner *arg1 = (virgil::crypto::VirgilStreamSigner *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::VirgilStreamSigner **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return 0;
  } 
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (arg1)->sign(*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamSigner_1sign_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilStreamSigner *arg1 = (virgil::crypto::VirgilStreamSigner *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::VirgilStreamSigner **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return 0;
  } 
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->sign(*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamSigner_1verify(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jbyteArray jarg3, jbyteArray jarg4) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilStreamSigner *arg1 = (virgil::crypto::VirgilStreamSigner *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::VirgilStreamSigner **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return 0;
  } 
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (bool)(arg1)->verify(*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilStreamSigner(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilStreamSigner *arg1 = (virgil::crypto::VirgilStreamSigner *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilStreamSigner **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamCipher_1encrypt_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jboolean jarg4) {
  virgil::crypto::VirgilStreamCipher *arg1 = (virgil::crypto::VirgilStreamCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  bool arg4 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilStreamCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  arg4 = jarg4 ? true : false; 
  {
    try {
      (arg1)->encrypt(*arg2,*arg3,arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamCipher_1encrypt_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_) {
  virgil::crypto::VirgilStreamCipher *arg1 = (virgil::crypto::VirgilStreamCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilStreamCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  {
    try {
      (arg1)->encrypt(*arg2,*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamCipher_1decryptWithKey_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jbyteArray jarg4, jbyteArray jarg5, jbyteArray jarg6) {
  virgil::crypto::VirgilStreamCipher *arg1 = (virgil::crypto::VirgilStreamCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray *arg5 = 0 ;
  virgil::crypto::VirgilByteArray *arg6 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilStreamCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  if(!jarg5) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg5_pdata = (jbyte *)jenv->GetByteArrayElements(jarg5, 0);
  size_t arg5_size = (size_t)jenv->GetArrayLength(jarg5);
  if (!arg5_pdata) return ;
  virgil::crypto::VirgilByteArray arg5_data(arg5_pdata, arg5_pdata + arg5_size);
  arg5 = &arg5_data;
  jenv->ReleaseByteArrayElements(jarg5, arg5_pdata, 0);
  
  if(!jarg6) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg6_pdata = (jbyte *)jenv->GetByteArrayElements(jarg6, 0);
  size_t arg6_size = (size_t)jenv->GetArrayLength(jarg6);
  if (!arg6_pdata) return ;
  virgil::crypto::VirgilByteArray arg6_data(arg6_pdata, arg6_pdata + arg6_size);
  arg6 = &arg6_data;
  jenv->ReleaseByteArrayElements(jarg6, arg6_pdata, 0);
  
  {
    try {
      (arg1)->decryptWithKey(*arg2,*arg3,(virgil::crypto::VirgilByteArray const &)*arg4,(virgil::crypto::VirgilByteArray const &)*arg5,(virgil::crypto::VirgilByteArray const &)*arg6);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamCipher_1decryptWithKey_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jbyteArray jarg4, jbyteArray jarg5) {
  virgil::crypto::VirgilStreamCipher *arg1 = (virgil::crypto::VirgilStreamCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray *arg5 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilStreamCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  if(!jarg5) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg5_pdata = (jbyte *)jenv->GetByteArrayElements(jarg5, 0);
  size_t arg5_size = (size_t)jenv->GetArrayLength(jarg5);
  if (!arg5_pdata) return ;
  virgil::crypto::VirgilByteArray arg5_data(arg5_pdata, arg5_pdata + arg5_size);
  arg5 = &arg5_data;
  jenv->ReleaseByteArrayElements(jarg5, arg5_pdata, 0);
  
  {
    try {
      (arg1)->decryptWithKey(*arg2,*arg3,(virgil::crypto::VirgilByteArray const &)*arg4,(virgil::crypto::VirgilByteArray const &)*arg5);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamCipher_1decryptWithPassword(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jbyteArray jarg4) {
  virgil::crypto::VirgilStreamCipher *arg1 = (virgil::crypto::VirgilStreamCipher *) 0 ;
  virgil::crypto::VirgilDataSource *arg2 = 0 ;
  virgil::crypto::VirgilDataSink *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::VirgilStreamCipher **)&jarg1; 
  arg2 = *(virgil::crypto::VirgilDataSource **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSource & reference is null");
    return ;
  } 
  arg3 = *(virgil::crypto::VirgilDataSink **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::VirgilDataSink & reference is null");
    return ;
  } 
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      (arg1)->decryptWithPassword(*arg2,*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilStreamCipher(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilStreamCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilStreamCipher *)new virgil::crypto::VirgilStreamCipher();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilStreamCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilStreamCipher(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilStreamCipher *arg1 = (virgil::crypto::VirgilStreamCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilStreamCipher **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1Min_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  virgil::crypto::VirgilTinyCipher::PackageSize result;
  
  (void)jenv;
  (void)jcls;
  result = (virgil::crypto::VirgilTinyCipher::PackageSize)virgil::crypto::VirgilTinyCipher::PackageSize_Min;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1Short_1SMS_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  virgil::crypto::VirgilTinyCipher::PackageSize result;
  
  (void)jenv;
  (void)jcls;
  result = (virgil::crypto::VirgilTinyCipher::PackageSize)virgil::crypto::VirgilTinyCipher::PackageSize_Short_SMS;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jint JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1Long_1SMS_1get(JNIEnv *jenv, jclass jcls) {
  jint jresult = 0 ;
  virgil::crypto::VirgilTinyCipher::PackageSize result;
  
  (void)jenv;
  (void)jcls;
  result = (virgil::crypto::VirgilTinyCipher::PackageSize)virgil::crypto::VirgilTinyCipher::PackageSize_Long_SMS;
  jresult = (jint)result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilTinyCipher_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  jlong jresult = 0 ;
  size_t arg1 ;
  virgil::crypto::VirgilTinyCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = (size_t)jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilTinyCipher *)new virgil::crypto::VirgilTinyCipher(arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilTinyCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilTinyCipher_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::VirgilTinyCipher *)new virgil::crypto::VirgilTinyCipher();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::VirgilTinyCipher **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1reset(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  {
    try {
      (arg1)->reset();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1encrypt(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      (arg1)->encrypt((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1encryptAndSign_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4, jbyteArray jarg5) {
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray *arg5 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  if(!jarg5) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg5_pdata = (jbyte *)jenv->GetByteArrayElements(jarg5, 0);
  size_t arg5_size = (size_t)jenv->GetArrayLength(jarg5);
  if (!arg5_pdata) return ;
  virgil::crypto::VirgilByteArray arg5_data(arg5_pdata, arg5_pdata + arg5_size);
  arg5 = &arg5_data;
  jenv->ReleaseByteArrayElements(jarg5, arg5_pdata, 0);
  
  {
    try {
      (arg1)->encryptAndSign((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4,(virgil::crypto::VirgilByteArray const &)*arg5);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1encryptAndSign_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return ;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return ;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      (arg1)->encryptAndSign((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1getPackageCount(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  size_t result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::VirgilTinyCipher const *)arg1)->getPackageCount();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jlong)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1getPackage(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  size_t arg2 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  arg2 = (size_t)jarg2; 
  {
    try {
      result = ((virgil::crypto::VirgilTinyCipher const *)arg1)->getPackage(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1addPackage(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return ;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return ;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      (arg1)->addPackage((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1isPackagesAccumulated(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  {
    try {
      result = (bool)((virgil::crypto::VirgilTinyCipher const *)arg1)->isPackagesAccumulated();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1decrypt_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->decrypt((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1decrypt_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->decrypt((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1verifyAndDecrypt_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (arg1)->verifyAndDecrypt((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilTinyCipher_1verifyAndDecrypt_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2, jbyteArray jarg3) {
  jbyteArray jresult = 0 ;
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  virgil::crypto::VirgilByteArray *arg3 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  virgil::crypto::VirgilByteArray arg3_data(arg3_pdata, arg3_pdata + arg3_size);
  arg3 = &arg3_data;
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (arg1)->verifyAndDecrypt((virgil::crypto::VirgilByteArray const &)*arg2,(virgil::crypto::VirgilByteArray const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilTinyCipher(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilTinyCipher *arg1 = (virgil::crypto::VirgilTinyCipher *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilTinyCipher **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilByteArrayUtils_1jsonToBytes(JNIEnv *jenv, jclass jcls, jstring jarg1) {
  jbyteArray jresult = 0 ;
  std::string *arg1 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg1_pstr = (const char *)jenv->GetStringUTFChars(jarg1, 0); 
  if (!arg1_pstr) return 0;
  std::string arg1_str(arg1_pstr);
  arg1 = &arg1_str;
  jenv->ReleaseStringUTFChars(jarg1, arg1_pstr); 
  {
    try {
      result = virgil::crypto::VirgilByteArrayUtils::jsonToBytes((std::string const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilByteArrayUtils_1stringToBytes(JNIEnv *jenv, jclass jcls, jstring jarg1) {
  jbyteArray jresult = 0 ;
  std::string *arg1 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg1_pstr = (const char *)jenv->GetStringUTFChars(jarg1, 0); 
  if (!arg1_pstr) return 0;
  std::string arg1_str(arg1_pstr);
  arg1 = &arg1_str;
  jenv->ReleaseStringUTFChars(jarg1, arg1_pstr); 
  {
    try {
      result = virgil::crypto::VirgilByteArrayUtils::stringToBytes((std::string const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilByteArrayUtils_1bytesToString(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jstring jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilByteArrayUtils::bytesToString((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilByteArrayUtils_1hexToBytes(JNIEnv *jenv, jclass jcls, jstring jarg1) {
  jbyteArray jresult = 0 ;
  std::string *arg1 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null string");
    return 0;
  }
  const char *arg1_pstr = (const char *)jenv->GetStringUTFChars(jarg1, 0); 
  if (!arg1_pstr) return 0;
  std::string arg1_str(arg1_pstr);
  arg1 = &arg1_str;
  jenv->ReleaseStringUTFChars(jarg1, arg1_pstr); 
  {
    try {
      result = virgil::crypto::VirgilByteArrayUtils::hexToBytes((std::string const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilByteArrayUtils_1bytesToHex_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jboolean jarg2) {
  jstring jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  bool arg2 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  arg2 = jarg2 ? true : false; 
  {
    try {
      result = virgil::crypto::VirgilByteArrayUtils::bytesToHex((virgil::crypto::VirgilByteArray const &)*arg1,arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT jstring JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilByteArrayUtils_1bytesToHex_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jstring jresult = 0 ;
  virgil::crypto::VirgilByteArray *arg1 = 0 ;
  std::string result;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  virgil::crypto::VirgilByteArray arg1_data(arg1_pdata, arg1_pdata + arg1_size);
  arg1 = &arg1_data;
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = virgil::crypto::VirgilByteArrayUtils::bytesToHex((virgil::crypto::VirgilByteArray const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = jenv->NewStringUTF((&result)->c_str()); 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilByteArrayUtils(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::VirgilByteArrayUtils *arg1 = (virgil::crypto::VirgilByteArrayUtils *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::VirgilByteArrayUtils **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSEncryptedMessage(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2, jbyteArray jarg3) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray arg1 ;
  virgil::crypto::VirgilByteArray arg2 ;
  virgil::crypto::VirgilByteArray arg3 ;
  virgil::crypto::pfs::VirgilPFSEncryptedMessage *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  (&arg1)->assign(arg1_pdata, arg1_pdata + arg1_size);
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  (&arg2)->assign(arg2_pdata, arg2_pdata + arg2_size);
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  (&arg3)->assign(arg3_pdata, arg3_pdata + arg3_size);
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSEncryptedMessage *)new virgil::crypto::pfs::VirgilPFSEncryptedMessage(arg1,arg2,arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSEncryptedMessage **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSEncryptedMessage_1getSessionIdentifier(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSEncryptedMessage *arg1 = (virgil::crypto::pfs::VirgilPFSEncryptedMessage *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSEncryptedMessage **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilByteArray *) &((virgil::crypto::pfs::VirgilPFSEncryptedMessage const *)arg1)->getSessionIdentifier();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSEncryptedMessage_1getSalt(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSEncryptedMessage *arg1 = (virgil::crypto::pfs::VirgilPFSEncryptedMessage *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSEncryptedMessage **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilByteArray *) &((virgil::crypto::pfs::VirgilPFSEncryptedMessage const *)arg1)->getSalt();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSEncryptedMessage_1getCipherText(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSEncryptedMessage *arg1 = (virgil::crypto::pfs::VirgilPFSEncryptedMessage *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSEncryptedMessage **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilByteArray *) &((virgil::crypto::pfs::VirgilPFSEncryptedMessage const *)arg1)->getCipherText();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilPFSEncryptedMessage(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::pfs::VirgilPFSEncryptedMessage *arg1 = (virgil::crypto::pfs::VirgilPFSEncryptedMessage *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::pfs::VirgilPFSEncryptedMessage **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSPublicKey_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray arg1 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  (&arg1)->assign(arg1_pdata, arg1_pdata + arg1_size);
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPublicKey *)new virgil::crypto::pfs::VirgilPFSPublicKey(arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSPublicKey_1_1SWIG_11(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPublicKey *)new virgil::crypto::pfs::VirgilPFSPublicKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSPublicKey_1isEmpty(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *arg1 = (virgil::crypto::pfs::VirgilPFSPublicKey *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jarg1; 
  {
    try {
      result = (bool)((virgil::crypto::pfs::VirgilPFSPublicKey const *)arg1)->isEmpty();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSPublicKey_1getKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *arg1 = (virgil::crypto::pfs::VirgilPFSPublicKey *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilByteArray *) &((virgil::crypto::pfs::VirgilPFSPublicKey const *)arg1)->getKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilPFSPublicKey(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::pfs::VirgilPFSPublicKey *arg1 = (virgil::crypto::pfs::VirgilPFSPublicKey *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSPrivateKey_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray arg1 ;
  virgil::crypto::VirgilByteArray arg2 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  (&arg1)->assign(arg1_pdata, arg1_pdata + arg1_size);
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  (&arg2)->assign(arg2_pdata, arg2_pdata + arg2_size);
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPrivateKey *)new virgil::crypto::pfs::VirgilPFSPrivateKey(arg1,arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSPrivateKey_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray arg1 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  (&arg1)->assign(arg1_pdata, arg1_pdata + arg1_size);
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPrivateKey *)new virgil::crypto::pfs::VirgilPFSPrivateKey(arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSPrivateKey_1_1SWIG_12(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPrivateKey *)new virgil::crypto::pfs::VirgilPFSPrivateKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSPrivateKey_1isEmpty(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *arg1 = (virgil::crypto::pfs::VirgilPFSPrivateKey *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jarg1; 
  {
    try {
      result = (bool)((virgil::crypto::pfs::VirgilPFSPrivateKey const *)arg1)->isEmpty();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSPrivateKey_1getKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *arg1 = (virgil::crypto::pfs::VirgilPFSPrivateKey *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilByteArray *) &((virgil::crypto::pfs::VirgilPFSPrivateKey const *)arg1)->getKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSPrivateKey_1getPassword(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *arg1 = (virgil::crypto::pfs::VirgilPFSPrivateKey *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilByteArray *) &((virgil::crypto::pfs::VirgilPFSPrivateKey const *)arg1)->getPassword();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSPrivateKey_1_1SWIG_13(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *arg1 = 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jarg1;
  if (!arg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::pfs::VirgilPFSPrivateKey const & reference is null");
    return 0;
  } 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPrivateKey *)new virgil::crypto::pfs::VirgilPFSPrivateKey((virgil::crypto::pfs::VirgilPFSPrivateKey const &)*arg1);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilPFSPrivateKey(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::pfs::VirgilPFSPrivateKey *arg1 = (virgil::crypto::pfs::VirgilPFSPrivateKey *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSInitiatorPublicInfo(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPublicKey arg1 ;
  virgil::crypto::pfs::VirgilPFSPublicKey arg2 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *argp1 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *argp2 ;
  virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  argp1 = *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jarg1; 
  if (!argp1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPublicKey");
    return 0;
  }
  arg1 = *argp1; 
  argp2 = *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jarg2; 
  if (!argp2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPublicKey");
    return 0;
  }
  arg2 = *argp2; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo *)new virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo(arg1,arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSInitiatorPublicInfo_1getIdentityPublicKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo *arg1 = (virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo *) 0 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo **)&jarg1; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPublicKey *) &((virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo const *)arg1)->getIdentityPublicKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSInitiatorPublicInfo_1getEphemeralPublicKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo *arg1 = (virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo *) 0 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo **)&jarg1; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPublicKey *) &((virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo const *)arg1)->getEphemeralPublicKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilPFSInitiatorPublicInfo(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo *arg1 = (virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSInitiatorPrivateInfo(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey arg1 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey arg2 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *argp1 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *argp2 ;
  virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  argp1 = *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jarg1; 
  if (!argp1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPrivateKey");
    return 0;
  }
  arg1 = *argp1; 
  argp2 = *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jarg2; 
  if (!argp2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPrivateKey");
    return 0;
  }
  arg2 = *argp2; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo *)new virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo(arg1,arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSInitiatorPrivateInfo_1getIdentityPrivateKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo *arg1 = (virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo *) 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo **)&jarg1; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPrivateKey *) &((virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo const *)arg1)->getIdentityPrivateKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSInitiatorPrivateInfo_1getEphemeralPrivateKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo *arg1 = (virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo *) 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo **)&jarg1; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPrivateKey *) &((virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo const *)arg1)->getEphemeralPrivateKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilPFSInitiatorPrivateInfo(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo *arg1 = (virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSResponderPublicInfo_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPublicKey arg1 ;
  virgil::crypto::pfs::VirgilPFSPublicKey arg2 ;
  virgil::crypto::pfs::VirgilPFSPublicKey arg3 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *argp1 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *argp2 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *argp3 ;
  virgil::crypto::pfs::VirgilPFSResponderPublicInfo *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  argp1 = *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jarg1; 
  if (!argp1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPublicKey");
    return 0;
  }
  arg1 = *argp1; 
  argp2 = *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jarg2; 
  if (!argp2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPublicKey");
    return 0;
  }
  arg2 = *argp2; 
  argp3 = *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jarg3; 
  if (!argp3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPublicKey");
    return 0;
  }
  arg3 = *argp3; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSResponderPublicInfo *)new virgil::crypto::pfs::VirgilPFSResponderPublicInfo(arg1,arg2,arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSResponderPublicInfo **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSResponderPublicInfo_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPublicKey arg1 ;
  virgil::crypto::pfs::VirgilPFSPublicKey arg2 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *argp1 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *argp2 ;
  virgil::crypto::pfs::VirgilPFSResponderPublicInfo *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  argp1 = *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jarg1; 
  if (!argp1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPublicKey");
    return 0;
  }
  arg1 = *argp1; 
  argp2 = *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jarg2; 
  if (!argp2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPublicKey");
    return 0;
  }
  arg2 = *argp2; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSResponderPublicInfo *)new virgil::crypto::pfs::VirgilPFSResponderPublicInfo(arg1,arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSResponderPublicInfo **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSResponderPublicInfo_1getIdentityPublicKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSResponderPublicInfo *arg1 = (virgil::crypto::pfs::VirgilPFSResponderPublicInfo *) 0 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSResponderPublicInfo **)&jarg1; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPublicKey *) &((virgil::crypto::pfs::VirgilPFSResponderPublicInfo const *)arg1)->getIdentityPublicKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSResponderPublicInfo_1getLongTermPublicKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSResponderPublicInfo *arg1 = (virgil::crypto::pfs::VirgilPFSResponderPublicInfo *) 0 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSResponderPublicInfo **)&jarg1; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPublicKey *) &((virgil::crypto::pfs::VirgilPFSResponderPublicInfo const *)arg1)->getLongTermPublicKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSResponderPublicInfo_1getOneTimePublicKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSResponderPublicInfo *arg1 = (virgil::crypto::pfs::VirgilPFSResponderPublicInfo *) 0 ;
  virgil::crypto::pfs::VirgilPFSPublicKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSResponderPublicInfo **)&jarg1; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPublicKey *) &((virgil::crypto::pfs::VirgilPFSResponderPublicInfo const *)arg1)->getOneTimePublicKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPublicKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilPFSResponderPublicInfo(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::pfs::VirgilPFSResponderPublicInfo *arg1 = (virgil::crypto::pfs::VirgilPFSResponderPublicInfo *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::pfs::VirgilPFSResponderPublicInfo **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSResponderPrivateInfo_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey arg1 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey arg2 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey arg3 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *argp1 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *argp2 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *argp3 ;
  virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  argp1 = *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jarg1; 
  if (!argp1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPrivateKey");
    return 0;
  }
  arg1 = *argp1; 
  argp2 = *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jarg2; 
  if (!argp2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPrivateKey");
    return 0;
  }
  arg2 = *argp2; 
  argp3 = *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jarg3; 
  if (!argp3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPrivateKey");
    return 0;
  }
  arg3 = *argp3; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *)new virgil::crypto::pfs::VirgilPFSResponderPrivateInfo(arg1,arg2,arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSResponderPrivateInfo **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSResponderPrivateInfo_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey arg1 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey arg2 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *argp1 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *argp2 ;
  virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  argp1 = *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jarg1; 
  if (!argp1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPrivateKey");
    return 0;
  }
  arg1 = *argp1; 
  argp2 = *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jarg2; 
  if (!argp2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSPrivateKey");
    return 0;
  }
  arg2 = *argp2; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *)new virgil::crypto::pfs::VirgilPFSResponderPrivateInfo(arg1,arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSResponderPrivateInfo **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSResponderPrivateInfo_1getIdentityPrivateKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *arg1 = (virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *) 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSResponderPrivateInfo **)&jarg1; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPrivateKey *) &((virgil::crypto::pfs::VirgilPFSResponderPrivateInfo const *)arg1)->getIdentityPrivateKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSResponderPrivateInfo_1getLongTermPrivateKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *arg1 = (virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *) 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSResponderPrivateInfo **)&jarg1; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPrivateKey *) &((virgil::crypto::pfs::VirgilPFSResponderPrivateInfo const *)arg1)->getLongTermPrivateKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSResponderPrivateInfo_1getOneTimePrivateKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *arg1 = (virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *) 0 ;
  virgil::crypto::pfs::VirgilPFSPrivateKey *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSResponderPrivateInfo **)&jarg1; 
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSPrivateKey *) &((virgil::crypto::pfs::VirgilPFSResponderPrivateInfo const *)arg1)->getOneTimePrivateKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSPrivateKey **)&jresult = result; 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilPFSResponderPrivateInfo(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *arg1 = (virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::pfs::VirgilPFSResponderPrivateInfo **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSSession_1_1SWIG_10(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSSession *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSSession *)new virgil::crypto::pfs::VirgilPFSSession();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSSession **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFSSession_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jbyteArray jarg1, jbyteArray jarg2, jbyteArray jarg3, jbyteArray jarg4) {
  jlong jresult = 0 ;
  virgil::crypto::VirgilByteArray arg1 ;
  virgil::crypto::VirgilByteArray arg2 ;
  virgil::crypto::VirgilByteArray arg3 ;
  virgil::crypto::VirgilByteArray arg4 ;
  virgil::crypto::pfs::VirgilPFSSession *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  if(!jarg1) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg1_pdata = (jbyte *)jenv->GetByteArrayElements(jarg1, 0);
  size_t arg1_size = (size_t)jenv->GetArrayLength(jarg1);
  if (!arg1_pdata) return 0;
  (&arg1)->assign(arg1_pdata, arg1_pdata + arg1_size);
  jenv->ReleaseByteArrayElements(jarg1, arg1_pdata, 0);
  
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  (&arg2)->assign(arg2_pdata, arg2_pdata + arg2_size);
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  if(!jarg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg3_pdata = (jbyte *)jenv->GetByteArrayElements(jarg3, 0);
  size_t arg3_size = (size_t)jenv->GetArrayLength(jarg3);
  if (!arg3_pdata) return 0;
  (&arg3)->assign(arg3_pdata, arg3_pdata + arg3_size);
  jenv->ReleaseByteArrayElements(jarg3, arg3_pdata, 0);
  
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  (&arg4)->assign(arg4_pdata, arg4_pdata + arg4_size);
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFSSession *)new virgil::crypto::pfs::VirgilPFSSession(arg1,arg2,arg3,arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSSession **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jboolean JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSSession_1isEmpty(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jboolean jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSSession *arg1 = (virgil::crypto::pfs::VirgilPFSSession *) 0 ;
  bool result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSSession **)&jarg1; 
  {
    try {
      result = (bool)((virgil::crypto::pfs::VirgilPFSSession const *)arg1)->isEmpty();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  jresult = (jboolean)result; 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSSession_1getIdentifier(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSSession *arg1 = (virgil::crypto::pfs::VirgilPFSSession *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSSession **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilByteArray *) &((virgil::crypto::pfs::VirgilPFSSession const *)arg1)->getIdentifier();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSSession_1getEncryptionSecretKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSSession *arg1 = (virgil::crypto::pfs::VirgilPFSSession *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSSession **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilByteArray *) &((virgil::crypto::pfs::VirgilPFSSession const *)arg1)->getEncryptionSecretKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSSession_1getDecryptionSecretKey(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSSession *arg1 = (virgil::crypto::pfs::VirgilPFSSession *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSSession **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilByteArray *) &((virgil::crypto::pfs::VirgilPFSSession const *)arg1)->getDecryptionSecretKey();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFSSession_1getAdditionalData(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::pfs::VirgilPFSSession *arg1 = (virgil::crypto::pfs::VirgilPFSSession *) 0 ;
  virgil::crypto::VirgilByteArray *temp ;
  virgil::crypto::VirgilByteArray *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFSSession **)&jarg1; 
  {
    try {
      result = (virgil::crypto::VirgilByteArray *) &((virgil::crypto::pfs::VirgilPFSSession const *)arg1)->getAdditionalData();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  temp = result;
  jresult = jenv->NewByteArray(temp->size());
  jenv->SetByteArrayRegion(jresult, 0, temp->size(), (const jbyte *)(&(*temp)[0]));
  
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilPFSSession(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::pfs::VirgilPFSSession *arg1 = (virgil::crypto::pfs::VirgilPFSSession *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::pfs::VirgilPFSSession **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_new_1VirgilPFS(JNIEnv *jenv, jclass jcls) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFS *result = 0 ;
  
  (void)jenv;
  (void)jcls;
  {
    try {
      result = (virgil::crypto::pfs::VirgilPFS *)new virgil::crypto::pfs::VirgilPFS();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFS **)&jresult = result; 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFS_1startInitiatorSession_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jbyteArray jarg4) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFS *arg1 = (virgil::crypto::pfs::VirgilPFS *) 0 ;
  virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo *arg2 = 0 ;
  virgil::crypto::pfs::VirgilPFSResponderPublicInfo *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::pfs::VirgilPFSSession result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::pfs::VirgilPFS **)&jarg1; 
  arg2 = *(virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo const & reference is null");
    return 0;
  } 
  arg3 = *(virgil::crypto::pfs::VirgilPFSResponderPublicInfo **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::pfs::VirgilPFSResponderPublicInfo const & reference is null");
    return 0;
  } 
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (arg1)->startInitiatorSession((virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo const &)*arg2,(virgil::crypto::pfs::VirgilPFSResponderPublicInfo const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSSession **)&jresult = new virgil::crypto::pfs::VirgilPFSSession((const virgil::crypto::pfs::VirgilPFSSession &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFS_1startInitiatorSession_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFS *arg1 = (virgil::crypto::pfs::VirgilPFS *) 0 ;
  virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo *arg2 = 0 ;
  virgil::crypto::pfs::VirgilPFSResponderPublicInfo *arg3 = 0 ;
  virgil::crypto::pfs::VirgilPFSSession result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::pfs::VirgilPFS **)&jarg1; 
  arg2 = *(virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo const & reference is null");
    return 0;
  } 
  arg3 = *(virgil::crypto::pfs::VirgilPFSResponderPublicInfo **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::pfs::VirgilPFSResponderPublicInfo const & reference is null");
    return 0;
  } 
  {
    try {
      result = (arg1)->startInitiatorSession((virgil::crypto::pfs::VirgilPFSInitiatorPrivateInfo const &)*arg2,(virgil::crypto::pfs::VirgilPFSResponderPublicInfo const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSSession **)&jresult = new virgil::crypto::pfs::VirgilPFSSession((const virgil::crypto::pfs::VirgilPFSSession &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFS_1startResponderSession_1_1SWIG_10(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_, jbyteArray jarg4) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFS *arg1 = (virgil::crypto::pfs::VirgilPFS *) 0 ;
  virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *arg2 = 0 ;
  virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo *arg3 = 0 ;
  virgil::crypto::VirgilByteArray *arg4 = 0 ;
  virgil::crypto::pfs::VirgilPFSSession result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::pfs::VirgilPFS **)&jarg1; 
  arg2 = *(virgil::crypto::pfs::VirgilPFSResponderPrivateInfo **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::pfs::VirgilPFSResponderPrivateInfo const & reference is null");
    return 0;
  } 
  arg3 = *(virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo const & reference is null");
    return 0;
  } 
  if(!jarg4) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg4_pdata = (jbyte *)jenv->GetByteArrayElements(jarg4, 0);
  size_t arg4_size = (size_t)jenv->GetArrayLength(jarg4);
  if (!arg4_pdata) return 0;
  virgil::crypto::VirgilByteArray arg4_data(arg4_pdata, arg4_pdata + arg4_size);
  arg4 = &arg4_data;
  jenv->ReleaseByteArrayElements(jarg4, arg4_pdata, 0);
  
  {
    try {
      result = (arg1)->startResponderSession((virgil::crypto::pfs::VirgilPFSResponderPrivateInfo const &)*arg2,(virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo const &)*arg3,(virgil::crypto::VirgilByteArray const &)*arg4);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSSession **)&jresult = new virgil::crypto::pfs::VirgilPFSSession((const virgil::crypto::pfs::VirgilPFSSession &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFS_1startResponderSession_1_1SWIG_11(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_, jlong jarg3, jobject jarg3_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFS *arg1 = (virgil::crypto::pfs::VirgilPFS *) 0 ;
  virgil::crypto::pfs::VirgilPFSResponderPrivateInfo *arg2 = 0 ;
  virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo *arg3 = 0 ;
  virgil::crypto::pfs::VirgilPFSSession result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  (void)jarg3_;
  arg1 = *(virgil::crypto::pfs::VirgilPFS **)&jarg1; 
  arg2 = *(virgil::crypto::pfs::VirgilPFSResponderPrivateInfo **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::pfs::VirgilPFSResponderPrivateInfo const & reference is null");
    return 0;
  } 
  arg3 = *(virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo **)&jarg3;
  if (!arg3) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo const & reference is null");
    return 0;
  } 
  {
    try {
      result = (arg1)->startResponderSession((virgil::crypto::pfs::VirgilPFSResponderPrivateInfo const &)*arg2,(virgil::crypto::pfs::VirgilPFSInitiatorPublicInfo const &)*arg3);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSSession **)&jresult = new virgil::crypto::pfs::VirgilPFSSession((const virgil::crypto::pfs::VirgilPFSSession &)result); 
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFS_1encrypt(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jbyteArray jarg2) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFS *arg1 = (virgil::crypto::pfs::VirgilPFS *) 0 ;
  virgil::crypto::VirgilByteArray *arg2 = 0 ;
  SwigValueWrapper< virgil::crypto::pfs::VirgilPFSEncryptedMessage > result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFS **)&jarg1; 
  if(!jarg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "null byte array");
    return 0;
  }
  jbyte *arg2_pdata = (jbyte *)jenv->GetByteArrayElements(jarg2, 0);
  size_t arg2_size = (size_t)jenv->GetArrayLength(jarg2);
  if (!arg2_pdata) return 0;
  virgil::crypto::VirgilByteArray arg2_data(arg2_pdata, arg2_pdata + arg2_size);
  arg2 = &arg2_data;
  jenv->ReleaseByteArrayElements(jarg2, arg2_pdata, 0);
  
  {
    try {
      result = (arg1)->encrypt((virgil::crypto::VirgilByteArray const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSEncryptedMessage **)&jresult = new virgil::crypto::pfs::VirgilPFSEncryptedMessage((const virgil::crypto::pfs::VirgilPFSEncryptedMessage &)result); 
  return jresult;
}


SWIGEXPORT jbyteArray JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFS_1decrypt(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_) {
  jbyteArray jresult = 0 ;
  virgil::crypto::pfs::VirgilPFS *arg1 = (virgil::crypto::pfs::VirgilPFS *) 0 ;
  virgil::crypto::pfs::VirgilPFSEncryptedMessage *arg2 = 0 ;
  virgil::crypto::VirgilByteArray result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::pfs::VirgilPFS **)&jarg1; 
  arg2 = *(virgil::crypto::pfs::VirgilPFSEncryptedMessage **)&jarg2;
  if (!arg2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "virgil::crypto::pfs::VirgilPFSEncryptedMessage const & reference is null");
    return 0;
  } 
  {
    try {
      result = ((virgil::crypto::pfs::VirgilPFS const *)arg1)->decrypt((virgil::crypto::pfs::VirgilPFSEncryptedMessage const &)*arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  
  jresult = jenv->NewByteArray((&result)->size());
  jenv->SetByteArrayRegion(jresult, 0, (&result)->size(), (const jbyte *)&result[0]);
  
  return jresult;
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFS_1getSession(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_) {
  jlong jresult = 0 ;
  virgil::crypto::pfs::VirgilPFS *arg1 = (virgil::crypto::pfs::VirgilPFS *) 0 ;
  virgil::crypto::pfs::VirgilPFSSession result;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  arg1 = *(virgil::crypto::pfs::VirgilPFS **)&jarg1; 
  {
    try {
      result = ((virgil::crypto::pfs::VirgilPFS const *)arg1)->getSession();
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return 0;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return 0;
    }
    
    
    
    
    
    
    
    
  }
  *(virgil::crypto::pfs::VirgilPFSSession **)&jresult = new virgil::crypto::pfs::VirgilPFSSession((const virgil::crypto::pfs::VirgilPFSSession &)result); 
  return jresult;
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPFS_1setSession(JNIEnv *jenv, jclass jcls, jlong jarg1, jobject jarg1_, jlong jarg2, jobject jarg2_) {
  virgil::crypto::pfs::VirgilPFS *arg1 = (virgil::crypto::pfs::VirgilPFS *) 0 ;
  virgil::crypto::pfs::VirgilPFSSession arg2 ;
  virgil::crypto::pfs::VirgilPFSSession *argp2 ;
  
  (void)jenv;
  (void)jcls;
  (void)jarg1_;
  (void)jarg2_;
  arg1 = *(virgil::crypto::pfs::VirgilPFS **)&jarg1; 
  argp2 = *(virgil::crypto::pfs::VirgilPFSSession **)&jarg2; 
  if (!argp2) {
    SWIG_JavaThrowException(jenv, SWIG_JavaNullPointerException, "Attempt to dereference null virgil::crypto::pfs::VirgilPFSSession");
    return ;
  }
  arg2 = *argp2; 
  {
    try {
      (arg1)->setSession(arg2);
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_delete_1VirgilPFS(JNIEnv *jenv, jclass jcls, jlong jarg1) {
  virgil::crypto::pfs::VirgilPFS *arg1 = (virgil::crypto::pfs::VirgilPFS *) 0 ;
  
  (void)jenv;
  (void)jcls;
  arg1 = *(virgil::crypto::pfs::VirgilPFS **)&jarg1; 
  {
    try {
      delete arg1;
    }
    
    
    
    
    
    
    catch (const std::exception& exception) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, backtrace_message(exception).c_str());
      return ;
    }
    catch (...) {
      jclass clazz = jenv->FindClass("java/lang/Exception");
      jenv->ThrowNew(clazz, "Unknown exception");
      return ;
    }
    
    
    
    
    
    
    
    
  }
}


SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSKeyTransRecipient_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::cms::VirgilCMSKeyTransRecipient **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSPasswordRecipient_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::cms::VirgilCMSPasswordRecipient **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSEncryptedContent_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::cms::VirgilCMSEncryptedContent **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSEnvelopedData_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::cms::VirgilCMSEnvelopedData **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSContent_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::cms::VirgilCMSContent **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCMSContentInfo_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::cms::VirgilCMSContentInfo **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilHash_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::VirgilHash **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilKDF_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::VirgilKDF **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSymmetricCipher_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::VirgilSymmetricCipher **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilAsymmetricCipher_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::VirgilAsymmetricCipher **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBE_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::VirgilPBE **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilPBKDF_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::foundation::VirgilPBKDF **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCustomParams_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::foundation::asn1::VirgilAsn1Compatible **)&baseptr = *(virgil::crypto::VirgilCustomParams **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilCipher_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::VirgilCipherBase **)&baseptr = *(virgil::crypto::VirgilCipher **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilChunkCipher_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::VirgilCipherBase **)&baseptr = *(virgil::crypto::VirgilChunkCipher **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilSigner_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::VirgilSignerBase **)&baseptr = *(virgil::crypto::VirgilSigner **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamSigner_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::VirgilSignerBase **)&baseptr = *(virgil::crypto::VirgilStreamSigner **)&jarg1;
    return baseptr;
}

SWIGEXPORT jlong JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_VirgilStreamCipher_1SWIGUpcast(JNIEnv *jenv, jclass jcls, jlong jarg1) {
    jlong baseptr = 0;
    (void)jenv;
    (void)jcls;
    *(virgil::crypto::VirgilCipherBase **)&baseptr = *(virgil::crypto::VirgilStreamCipher **)&jarg1;
    return baseptr;
}

SWIGEXPORT void JNICALL Java_com_virgilsecurity_crypto_virgil_1crypto_1javaJNI_swig_1module_1init(JNIEnv *jenv, jclass jcls) {
  int i;
  
  static struct {
    const char *method;
    const char *signature;
  } methods[4] = {
    {
      "SwigDirector_VirgilDataSource_hasData", "(Lcom/virgilsecurity/crypto/VirgilDataSource;)Z" 
    },
    {
      "SwigDirector_VirgilDataSource_read", "(Lcom/virgilsecurity/crypto/VirgilDataSource;)[B" 
    },
    {
      "SwigDirector_VirgilDataSink_isGood", "(Lcom/virgilsecurity/crypto/VirgilDataSink;)Z" 
    },
    {
      "SwigDirector_VirgilDataSink_write", "(Lcom/virgilsecurity/crypto/VirgilDataSink;[B)V" 
    }
  };
  Swig::jclass_virgil_crypto_javaJNI = (jclass) jenv->NewGlobalRef(jcls);
  if (!Swig::jclass_virgil_crypto_javaJNI) return;
  for (i = 0; i < (int) (sizeof(methods)/sizeof(methods[0])); ++i) {
    Swig::director_method_ids[i] = jenv->GetStaticMethodID(jcls, methods[i].method, methods[i].signature);
    if (!Swig::director_method_ids[i]) return;
  }
}


#ifdef __cplusplus
}
#endif

