# DATABASE
## 1. What is the difference between optimistic locking and pessimistic locking?
   (https://medium.com/@saraswat.prateek1000/optimistic-v-s-pessimistic-locks-6be05ae97391)
   Pessimistic Locking is when you lock the record for your exclusive use until you have finished using it. 
   It has much better integrity than optimistic locking but requires you to be careful with your application design to avoid Deadlocks. 
   The disadvantage is that resource is locked from when you start the transaction until you finished the transaction. During that time the record is not available to other transactions.
   
   Optimistic Locking is a when you read a record, take note of a version number and check that the version hasn’t changed before you write the record back. 
   When you write the record back you filter the update on the version to make sure it’s atomic. Other transactions are able to concurrently access to the 
   resource and the possibility of conflicting changes is possible. At commit time, when the resource is about to be updated in persistent storage, the state of 
   the resource is read from storage again and compared to the state that was saved when the resource was first accessed in the transaction. If the two states differ,
   a conflicting update was made, and the transaction will be rolled back.

# C-SHARP
## 2. Explain Delegates and Usage with Events?
   A delegate in C# is a type that holds a reference to a method. Namely, a delegate can invoke a method. Events, on the other hand, are a way that a class can notify other classes when something happened. 

   ``` csharp 
   public delegate void MyDelegate(string message);
   public class MyClass{
      public event MyDelegate MyEvent;
      public void Trigger(){
        MyEvent!.Invoke("Hello");
      }
    }

    public class MyProgram{
        public static void Main(){
          var deneme = new MyClass();
          deneme.MyEvent+= (msg)=>{Console.WriteLine(msg);}
          deneme.Trigger();
        }
     } 
     ```
