using System;

namespace CSharpFeatures
{
    record class studentInfo(string StudentFName, string StudentMName, string StudentLName);

    public class CSharp7Features
    {
        public void Test()
        {
            //1.0 TUPLES
            var empInfo = getEmpInfo();
            Console.WriteLine("Emp info as  {empInfo .Item1} {empInfo .Item2} {empInfo .Item3} {empInfo .Item4}.");

            //1.1 Deconstruction
            //If we don't want to access whole tuple bundle or we just need internal values then we can use Deconstruction features of C# 7.0
            (string strFName, string strAdd, string strC, string strSt) = getEmpInfo();
            Console.WriteLine($"Address: {strAdd}, Country: {strC}");

            //2.0 Record Type
            //C# support record type, which is nothing but a container of a properties and variables,
            //most of the time classes are full with properties and variables, we need lot of code to just declare them
            //but with the help of Record Type you can reduce your effort, see below snippet
            var student = new studentInfo("Osman", "", "Sokuoğlu");
            Console.WriteLine($"Name: {student.StudentFName}, LastName: {student.StudentLName}");


            //3.0 Minimizing OUT
            //Before
            string strArguBefore;
            AssignVal(out strArguBefore);
            Console.WriteLine($"strArgu-Before: {strArguBefore}");

            //Now
            //C# 7.0 reduce your pain of writing extra code and you can just pass argument without initialize them, see below snippet
            AssignVal(out string strArgu);
            Console.WriteLine($"strArgu: {strArgu}");


            //4.0 Non-'NULL' able reference type
            //Null reference is really a headache for all programmers, it is a million dollar exception.
            //To deal with this problem C# 7.0 come with non-nullable reference types
            //? is for nullable value-type and '!' is for non-nullable reference type
            int objNullVal;     //non-nullable value type
            int? objNotNullVal;    //nullable value type
            string objNotNullRef; //non-nullable reference type
            string? objNullRef;  //nullable reference type

            objNullRef = null;   // this is nullable, so no problem in assigning
            objNotNullRef = null;   // Error, as objNotNullRef is non-nullable
            objNotNullRef = objNullRef;      // Error, as nullable object can not be refered

            Console.WriteLine(objNotNullRef.ToString()); // Not null so can convert to tostring
            Console.WriteLine(objNullRef.ToString()); // could be null

            if (objNullRef != null) { Console.WriteLine(objNullRef.ToString()); } // No error as we have already checked it
            Console.WriteLine(objNullRef!.Length); // No error


            //5.0 Pattern matching
            //C# 7.0 allows user to use pattern in IS statement and with SWITCH statement, so we can match pattern with any datatype,
            //patterns can be constant patterns, Type patterns, Var patterns. 
            object o = new { };
            // Constant pattern null
            if (o is null) Console.WriteLine("o is null");
            // Type pattern "int n"
            if (o is int n) Console.WriteLine($"o is int and has value: {n} ");
            // var pattern
            if (o is var x) Console.WriteLine($"x: {x}");

            //6.0 'return' by Ref
            //Have you tried to return your variable from method/function as Ref ? Yes, C# 7.0 allows you to do that. 
            //Infect you can pass a variable with Ref return them as Ref and also store them as Ref
            string[] values = { "a", "b", "c", "d" };
            ref string strSubstitute = ref getFromList("b", values);
            strSubstitute = "K"; // replaces 7 with 9 in the array
            Console.WriteLine(values[1]); // it prints "K"

            //7.0 Throw Exception from Expression
            //Now you can throw exception from your expression directly.
            var info = checkInfo("DontTestME!");
            Console.WriteLine(info); // it prints "K"

            //8.0 Discards
            //Discards are temporary, write-only variables used in assignments when you don't care about the value assigned.
            //They are particularly useful when deconstructing tuples and user-defined types, as well as when calling methods with out parameters.
            //Sometimes you don't need values returned from a method, especially when deconstructing tuples and methods with out parameters, for example:
            //Here we are not using parsed value so why to declare it, in C# 7 with the introduction of discards, you can solve this problem:
            if (bool.TryParse(arg1, out bool _))
            {
                // Logic here
            }
        }

        (string, string, string, string) getEmpInfo()
        {
            //read EmpInfo from database or any other source and just return them
            string strFirstName = "abc";
            string strAddress = "Address";
            string strCity = "City";
            string strState = "State";
            return (strFirstName, strAddress, strCity, strState); // tuple literal
        }

        void AssignVal(out string strName)
        {
            strName = "I am from OUT";
        }

        ref string getFromList(string strVal, string[] Values)
        {
            string foundValue = null;
            for (int i = 0; i < Values.Length; i++)
            {
                if (strVal == Values[i])
                    return ref Values[i]; //return location as ref not actual value
            }
            return ref Values[0];
        }

        public string checkInfo(string EmpName)
        {
            string[] empArr = EmpName.Split(",");
            return (empArr.Length > 0) ? empArr[0] : throw new Exception("Emp Info Not exist");
        }
    }
}
