using System;
using System.ComponentModel;

namespace CSharpFeatures
{
    public class CSharp12Features
    {
        public void Test()
        {
            //1.0 Primary constructors
            //Primary constructors are no longer restricted to record types. You can now create primary constructors in any class and struct. 
            //Adding a primary constructor to a class prevents the compiler from declaring an implicit parameterless constructor. 
            //CHECK ==> NamedItem class

            //2.0 Collection Expressions
            //The spread operator, .. in a collection expression replaces its argument with the elements from that collection. 
            int[] row0 = [1, 2, 3, 4, 5, 6, 7, 8];
            int[] row1 = [1, 2, 3];
            int[] single = [..row0, ..row1];

            //3.0 Default lambda parameters
            //You can now define default values for parameters on lambda expressions. The syntax and rules are the same as adding default values for arguments to any method or local function.
            var IncrementBy = (int source, int increment = 1) => source + increment;
            Console.WriteLine(IncrementBy(5)); // 6

            //4.0 Interceptors
            //C#’ın 12. versiyonuyla birlikte deneysel bir özellik olan interceptors tanıtıldı.
            //Interceptors, özel kodun belirli yöntem çağrılarını yönlendirmesine olanak tanır.
            //CHECK => MyIntercepterService class


            //5.0 nameof ile Erişilebilen Öğeler
            //nameof anahtar kelimesi, artık üye adları, başlatıcılar, statik üyeler ve niteliklerle çalışır.
            //CHECK => NameOf class
        }
    }

    //public class Person(string name, ing age)
    //{
    //    string Info => $"name:{name} and age:{age}"; 
    //}

    //[Features("InterceptorsPreview")]
    //public class MyIntercepterService
    //{
    //    [Interceptor(typeof(MyInterceptor))]
    //    public void DoSomething()
    //    {
    //        // Burada yapılacak işlem
    //    }
    //}

    internal class NameOf
    {
        public string S { get; } = "";
        public static int StaticField;
        public string NameOfLength { get; } = nameof(S.Length);

        public static void NameOfExamples()
        {
            Console.WriteLine(nameof(S.Length));
            Console.WriteLine(nameof(StaticField.MinValue));
        }

        [Description($"String {nameof(S.Length)}")]
        public int StringLength(string s)
        {
            return s.Length;
        }
    }
}
