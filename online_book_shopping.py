import mysql.connector
import stripe
from fastapi import FastAPI , Depends , HTTPException ,Request
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel , EmailStr , Field 
from typing import List , Optional , Literal
from jose import jwt , JWTError
from datetime import datetime , timedelta 
from passlib.context import CryptContext
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os

load_dotenv()

stripe.api_key = os.getenv("stripe.api_key")


secret_key ="mysecretkey"
refresh_secret_key = "my_refresh_secret_key"
hash_password = "HS256"
expire_time = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

app = FastAPI()

context = CryptContext(schemes=["bcrypt"] , deprecated = "auto")
jwt_token = OAuth2PasswordBearer(tokenUrl="login")


# rate limiting setup 
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)

def get_connection():
    try:
        return mysql.connector.connect(
        host="localhost",
        user="root",
        password="Naveen@123",
        database="online_bookstore",
        auth_plugin="mysql_native_password"
        )
    except mysql.connector.Error as e:
      raise HTTPException(status_code=500, detail=f"Database connection error: {str(e)}")
    
    
# rate limit exception handel 

@app.exception_handler(RateLimitExceeded)
async def ratelimit_exceed_handeler(request : Request , exc : RateLimitExceeded):
   return JSONResponse(
        status_code=429,
        content={"detail": "Too Many Requests"}
    )

# genrate token 

def create_token(data : dict , expire : timedelta):
   try:
     copy_data = data.copy()
     expire_time = datetime.utcnow() + expire
     copy_data.update({"exp":expire_time})
     token = jwt.encode(copy_data , secret_key , algorithm= hash_password)
     return token 
   except Exception as e:
      return str(e)


def create_refresh_token(data : dict , expire : timedelta):
   try:
     copy_data = data.copy()
     expire_time = datetime.utcnow() + expire
     copy_data.update({"exp":expire_time})
     token = jwt.encode(copy_data , refresh_secret_key , algorithm= hash_password)
     return token 
   except Exception as e:
      return str(e)

#  verify password

def verify_password(simple_password : str , hashed_password : str):
   try:
      if context.verify(simple_password , hashed_password):
         return True
      else:
         raise HTTPException(status_code=401 , detail= "incorrect password")
   except Exception as e:
      raise HTTPException(status_code=500 , detail= f"password varification failed{str(e)}")

# convert to hash password

def hashing_password(password):
   try:
      return context.hash(password)
   except Exception as e:
      raise HTTPException(status_code=500 , detail= f"password hashing failed {str(e)}")

# verify token 

def verify_token(token : str = Depends(jwt_token)):
   try:
      jwt_decode = jwt.decode(token , secret_key , algorithms= [hash_password])
      user_id = jwt_decode.get("user_id")
      if not user_id:
        raise HTTPException(status_code=401, detail="Invalid  token")
      return int(user_id)
   except JWTError:
        raise HTTPException(status_code=401, detail="Invalid  or expired token")
   

# verify admin 

def verify_admin(token : str = Depends(jwt_token)):
   try:
      admin_decode = jwt.decode(token , secret_key , algorithms= [hash_password])
      user_id = admin_decode.get("user_id")
      if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token")
      
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)
      query = "select role from users where user_id = %s"
      value = (user_id,)
      cursor.execute(query , value)
      user = cursor.fetchone()

      if not user or  user["role"] != "admin":
        raise HTTPException(status_code=403 , detail="only access can admin")
      return user_id
   except JWTError:
      raise HTTPException(status_code=401, detail="Invalid or expired token")
   finally:
      cursor.close()
      connection.close()


# basemodel pydentic 
class TokenModel(BaseModel):
   token: str

class UserResponse(BaseModel):
   user_id : int
   username : str
   email : EmailStr
   role : str
   created_at : datetime

class UserRegister(BaseModel):
   username : str
   email : EmailStr
   password_hash : str

class CreateBooks(BaseModel):
   title : str
   author : str
   category : str
   description : str
   price : float
   stock : int = 0

class UpdateBooks(BaseModel):
   book_id : int
   title : str
   author : str
   category : str
   description : str
   price : float
   stock : int = 0

class OrderItem(BaseModel):
    book_id: int
    quantity: int

class AddReviews(BaseModel):
   book_id : int
   rating : int = Field(..., ge=1, le=5)
   comment : Optional[str] = None

class UpdateStatus(BaseModel):
   order_id : int
   status: Literal['pending', 'shipped', 'delivered', 'cancelled', 'returned']

class PaymentStatus(BaseModel):
   order_id : int

class CreateCoupon(BaseModel):
   code: str
   discount_percent: int
   expiry_date: datetime
   is_active: bool = True 

class ApplyCoupen(BaseModel):
   order_id : int
   coupen_code : str

class WishlistItem(BaseModel):
   book_id: int

# register 

@app.post("/register",response_model = List[UserResponse])
@limiter.limit("2/minute")

def register(request : Request , register : List[UserRegister]):
   try:
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)

      for user in register:
         hash_pass = hashing_password(user.password_hash)
         query = """ insert into users ( username , email , password_hash)
                     values (%s , %s , %s)"""
         values = (user.username , user.email , hash_pass)
         cursor.execute(query , values)
      connection.commit()

      response_data = []
      for user in register:
         quarry = "select user_id , username , email , role , created_at from users where email = %s"
         value = (user.email,)
         cursor.execute(quarry , value)
         data = cursor.fetchone()
         if data:
            response_data.append(data)

      return response_data
   except Exception as e:
      connection.rollback()
      raise HTTPException(status_code=400 , detail= f"user registration faild {str(e)}")
   finally:
      cursor.close()
      connection.close()

# login users 

@app.post("/login")
@limiter.limit("3/minute")

def login(request : Request , log : OAuth2PasswordRequestForm = Depends()):
   try:
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)

      query = "select * from users where username = %s"
      value = (log.username,)
      cursor.execute(query , value)
      data = cursor.fetchone()

      if not data or not verify_password(log.password , data["password_hash"]):
         raise HTTPException(status_code= 401, detail="Invalid credentials" )
      access_token = create_token({"sub" : data["username"] , "user_id" : data["user_id"]} ,timedelta(minutes=expire_time))

      refresh_token = create_refresh_token({"sub": data["username"], "user_id": data["user_id"]}, timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS))
      return {"access_token ":access_token ,
            "refresh_token ": refresh_token,
             "token_type": "Bearer"}
   
   except Exception as e:
      raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
   finally:
      cursor.close()
      connection.close()


#refresh token
@app.post("/refresh")

def login_refresh(data : TokenModel, request : Request):
   try:
      decoding = jwt.decode(data.token , refresh_secret_key , algorithms= [hash_password])
      user_id = decoding.get("user_id")
      username = decoding.get("sub")
      if not user_id or not username:
         raise HTTPException(status_code=401, detail="Invalid refresh token")
      new_access_token = create_token({"sub" : username , "user_id": user_id} ,timedelta(minutes=expire_time))
      return {"new_token" :  new_access_token}
   except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")


# online_bookstore crud opreation 

# POST /books: Create a new book (only accessible to admins)

@app.post("/create/books")
@limiter.limit("1/minute")

def create(request : Request , books : List[CreateBooks] , token : str = Depends(verify_admin)):
   try:
      connection = get_connection()
      cursor = connection.cursor()

      book_count = 0
      query = """insert into books (title , author , category, description ,  price , stock)
                 values (%s,%s,%s,%s,%s,%s)"""
      for book in books:
         values = (book.title , book.author , book.category , book.description , book.price , book.stock)
         cursor.execute(query , values)
         if cursor.rowcount > 0:
            book_count+=1
      connection.commit()

      if book_count ==0:
         raise HTTPException(status_code=400 , detail= "no data created ")
      return {"books created sucessfullly  : books count " : len(books)}
   
   except Exception as e:
      connection.rollback()
      raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
   finally:
      cursor.close()
      connection.close()

# get book 

@app.get("/books/{book_id}")
@limiter.limit("5/minute")

def get_book(request : Request , book_id : int , token : str = Depends(verify_token)):
   try:
      if not book_id:
         raise HTTPException(status_code=401 , detail="provide your book id")
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)
      query = "select title , author , category , description , price , stock from books where book_id = %s"
      value = (book_id,)
      cursor.execute(query,value)
      book = cursor.fetchone()
      if not book:
            raise HTTPException(status_code=404, detail="Book not found")
      return book
   except Exception as e:
      raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
   finally:
      cursor.close()
      connection.close()

# GET /books: List all books (with filtering by category/author).

@app.get("/list/books")
@limiter.limit("3/minute")

def list_book(request : Request , category : Optional[str] = None , author : Optional[str] = None ,token : str = Depends(verify_token)):
   try:
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)
      

      if author and category:
         query = "select * from books where category = %s and author = %s"
         value = (category , author)
         cursor.execute(query , value)
         data = cursor.fetchall()
         return data
      
      elif category is not None:
         query = "select * from books where category = %s"
         value = (category,)
         cursor.execute(query , value)
         data = cursor.fetchall()
         return data
      
      elif author is not None:
         query = "select * from books where author = %s"
         value = (author,)
         cursor.execute(query,value)
         data = cursor.fetchall()
         return data
      
      else:
         query = "select * from books"
         cursor.execute(query)
         data = cursor.fetchall()
         return data
       
   except Exception as e:
      raise HTTPException(status_code=500, detail=f"Error fetching books: {str(e)}")
   finally:
      cursor.close()
      connection.close()


#  Update book details (only accessible to admins).

@app.put("/update/books")
@limiter.limit("2/minute")

def update_books(request : Request , update_book : List[UpdateBooks], token : str = Depends(verify_admin)):
   try:
      if not update_book:
         raise HTTPException(status_code=400 , detail="provide your update books")
      connection = get_connection()
      cursor = connection.cursor()

      update_count= 0
      query = """UPDATE books SET  title = %s , author = %s , category = %s , description = %s, price = %s , stock = %s
                 where book_id = %s"""
      
      for book in update_book:
         values = (book.title , book.author , book.category , book.description , book.price , book.stock , book.book_id)
         cursor.execute(query , values)
         if cursor.rowcount > 0:
            update_count += 1

      if update_count == 0:
         raise HTTPException(status_code=400 , detail = "not update books")
      connection.commit()
      return {"books update sucessfully : books update counts" : update_count}
   except  Exception as e:
      connection.rollback()
      raise HTTPException(status_code=500, detail=f"Error update books: {str(e)}")
   finally:
      cursor.close()
      connection.close()


# Delete a book (only accessible to admins).

@app.delete("/delete/books")
@limiter.limit("2/minute")

def delete_books(request : Request , book_id : List[int] , token : str = Depends(verify_admin)):
   try:
      if not book_id:
         raise HTTPException(status_code=400 , detail= "provide your book_id")
      connection = get_connection()
      cursor = connection.cursor()

      delete_count = 0
      query = "delete from books where book_id = %s"
      for book in book_id:
         value = (book,)
         cursor.execute(query , value)
         if cursor.rowcount > 0:
            delete_count += 1
      connection.commit()
      if delete_count ==0:
         raise HTTPException(status_code=400 , detail= "books not deleted")
      
      return {"data delete successfully : delete _count ": delete_count}
   except  Exception as e:
      connection.rollback()
      raise HTTPException(status_code=500, detail=f"Error delete books: {str(e)}")
   finally:
      cursor.close()
      connection.close()


# Create a new order.

@app.post("/create/order")
@limiter.limit("2/minute")

def create_order(request : Request , items : List[OrderItem] , token : str = Depends(verify_token)):
   try:
      if not items:
         raise HTTPException(status_code=400 , detail="provide your order")
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)
      
      order_book_count = 0 
      total_price = 0
      query = "select price ,stock from books where book_id = %s"
      for book in items:
         value = (book.book_id,)
         cursor.execute(query , value)
         books = cursor.fetchone()

         if not books:
            raise HTTPException(status_code=404, detail=f"Book with ID {book.book_id} not found")
         if books["stock"] < book.quantity:
            raise HTTPException(status_code= 404 , detail=f"Not enough stock avalible stock is :  {books['stock']}")
         
         item_price = book.quantity * books["price"]
         
         total_price += item_price
      
      
     
         quary = "INSERT INTO orders (user_id, book_id, quantity, total_price, status) VALUES (%s, %s, %s, %s, %s)"
         values = (token , book.book_id , book.quantity , item_price , "pending")
         cursor.execute(quary , values)

         quarry = "update books SET stock = stock - %s WHERE book_id = %s"
         valu = (book.quantity , book.book_id)
         cursor.execute(quarry , valu)
         if cursor.rowcount > 0:
            order_book_count += 1
      connection.commit()
      
      if order_book_count == 0:
         raise HTTPException(status_code=400 , detail= "order not success" )
      return {"order placed sucessfull : total price is : ": total_price}
   
   except Exception as e:
      connection.rollback()
      raise HTTPException(status_code=500, detail=f"Error order books: {str(e)}")
   finally:
      cursor.close()
      connection.close()


# View a user's order history

@app.get("/order/history")
@limiter.limit("2/minute")

def order_history(request : Request , token : str = Depends(verify_token)):
   try:
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)
      query = """select b.title  , b.author  , o.order_id , o.quantity , o.total_price , o.book_id , o.status , o.order_date
                 from orders as o
                 join books as b
                 on o.book_id = b.book_id
                 where o.user_id = %s
                 order by o.order_date desc"""
      value = (token,)
      cursor.execute(query , value)
      data = cursor.fetchall()
      if not data:
         return("no order found")
      return data
   
   except Exception as e:
      raise HTTPException(status_code=500, detail=f"Error view order : {str(e)}")
   finally:
      cursor.close()
      connection.close()


# reviews: Add a review for a book.

@app.post("/add/reviews")
@limiter.limit("5/minute")

def add_review(request : Request , reviews : List[AddReviews] , token : str = Depends(verify_token)):
   try:
      connection = get_connection()
      cursor = connection.cursor()

      count = 0
      query = "insert into reviews (book_id , rating , comment , user_id) values (%s , %s , %s , %s)"
      for review in reviews:
         values = (review.book_id , review.rating , review.comment , token)
         cursor.execute(query , values)
         if cursor.rowcount > 0:
            count += 1
      connection.commit()
      if count == 0:
         raise HTTPException(status_code=400 , detail= "add reviews failed ")
      return {"add reviews sucessfully : review count " : count}
   
   except Exception as e:
      connection.rollback()
      raise HTTPException(status_code=500, detail=f"Error reviews : {str(e)}")
   finally:
      cursor.close()
      connection.close()
   
# update the order status (e.g., when the order is shipped or delivered).

@app.put("/update/order/status")
@limiter.limit("3/minute")

def update_status(request : Request , chng_status : List[UpdateStatus] , token : str = Depends(verify_token)):
   try:
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)
      
      count = 0
      query = "UPDATE orders SET status = %s WHERE order_id = %s"
      for data in chng_status:
        values = (data.status, data.order_id)
        cursor.execute(query, values)
        if cursor.rowcount>0:
           count +=1

      connection.commit()

      if count == 0:
         raise HTTPException(status_code=404, detail="Order not found or status not updated")

      return {"message": f" order updated count is :{count}"}

   except Exception as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=f"Error updating order status: {str(e)}")

   finally:
        cursor.close()
        connection.close()


# Payment Integration: Integrate with a payment gateway (like Stripe) to process payments for orders.

@app.post("/create/payment")
@limiter.limit("5/minute")

def payment(request : Request , pay : List[PaymentStatus] , token : str = Depends(verify_token)):
   try:
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)

      count = 0
      quary = """insert into payments (order_id , user_id , amount , payment_status , stripe_charge_id)
                 values (%s , %s , %s , %s , %s)"""
      
      for payment in pay:
         query = "select total_price , status from orders where user_id = %s and order_id = %s"
         value = (token, payment.order_id)
         cursor.execute(query , value)
         data = cursor.fetchone()
         if not data:
           raise HTTPException(status_code= 404 , detail = "order not found ")
         if data["status"] == "delivered":
           raise HTTPException(status_code=400 , detail = "already payment")
         totalprice = data["total_price"]

         intent = stripe.PaymentIntent.create(
         amount = int(data["total_price"] * 100),
         currency= "inr"
      )

         values = (payment.order_id , token , totalprice , "completed" , intent.id)
         cursor.execute(quary , values)

         quarry = "update orders set status = %s  WHERE order_id = %s"
         valu = ("delivered" , payment.order_id)
         cursor.execute(quarry , valu)

         if cursor.rowcount>0:
            count += 1
      if count ==0:
         raise HTTPException(status_code=404, detail="payment not success")
      connection.commit()
      return {"sucessfully payemt and total payment order count is ": count}
   except Exception as e:
        connection.rollback()
        raise HTTPException(status_code=500, detail=f"Payment Error: {str(e)}")
   finally:
        cursor.close()
        connection.close()

# ...............................................
# Implement coupon codes that users can apply to reduce the total price.

@app.post("/create/coupen")
@limiter.limit("2/minute")

def create_coupen(request : Request , coupen : CreateCoupon , token : str = Depends(verify_admin)):
   try:
      connection = get_connection()
      cursor = connection.cursor()
      query = "insert into coupons (code , discount_percent , expiry_date , is_active) values (%s , %s , %s , %s)"
      values = (coupen.code , coupen.discount_percent , coupen.expiry_date , coupen.is_active)
      cursor.execute(query , values)
      connection.commit()
      return ("coupon create sucessfully")
   except Exception as e:
      connection.rollback()
      raise HTTPException(status_code=500 , detail=f"database error{str(e)}")
   finally:
      cursor.close()
      connection.close()


#apply coupon 

@app.post("/apply/coupen")
@limiter.limit("3/minute")

def apply_coupen(request: Request , apply : List[ApplyCoupen] , token : str = Depends(verify_token)):
   try:
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)
      
      count = 0
      for coupen in apply:
         query = "select * from coupons where code = %s and is_active = true and expiry_date > now()"
         value = (coupen.coupen_code ,)
         cursor.execute(query , value)
         cupen = cursor.fetchone()
         if not cupen:
            raise HTTPException(status_code=404 , detail="invalid and expire token")
         
         quary = "select total_price from orders where order_id = %s and user_id = %s"
         values = (coupen.order_id , token)
         cursor.execute(quary , values)
         order = cursor.fetchone()
         if not order:
            raise HTTPException(status_code=404, detail="Order not found")
         
         discount_amount = (order["total_price"] * cupen["discount_percent"]) //100
         discount_price = order["total_price"] - discount_amount

         quarry = "update orders set total_price = %s where order_id = %s"
         valu = (discount_price , coupen.order_id)
         cursor.execute(quarry , valu)

         if cursor.rowcount>0:
            count += 1
      if count ==0:
         raise HTTPException(status_code=404, detail="invalid discount")
      connection.commit()
      return {"sucessfully discount ": count}
   
   except Exception as e:
      connection.rollback()
      raise HTTPException(status_code=500 , detail=f"database error{str(e)}")
   finally:
      cursor.close()
      connection.close()


#  Allow users to create a wishlist of books they plan to buy later.

@app.post("/add/wishlist")
@limiter.limit("3/minute")

def add_wish(request : Request , wishlist : List[WishlistItem] , token : str = Depends(verify_token)):
   try:
      connection = get_connection()
      cursor = connection.cursor()
      count = 0
      query = "insert into wishlists (book_id , user_id) values (%s , %s)"
      for wish in wishlist:
         values = (wish.book_id , token)
         cursor.execute(query , values)
         if cursor.rowcount>0:
            count +=1
      if count == 0:
        raise HTTPException(status_code=404 , detail= " wishlist not add")
      connection.commit()
      return {"add wishlist sucessfully and count : " :count}
   
   except Exception as e:
      connection.rollback()
      raise HTTPException(status_code=500 , detail=f"database error{str(e)}")
   finally:
      cursor.close()
      connection.close()
   

# get wishlist 

@app.get("/wishlist")
@limiter.limit("3/minute")

def get_wish(request : Request , token : str = Depends(verify_token)):
   try:
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)
      query = """select b.book_id , b.title , b.author , b.category , b.price from books as b
                 join wishlists as w
                 on w.book_id = b.book_id
                 where w.user_id = %s"""
      values = (token,)
      cursor.execute(query , values)
      data = cursor.fetchall()
      return {"wishlist": data}
   
   except Exception as e:
      raise HTTPException(status_code=500 , detail=f"database error{str(e)}")
   finally:
      cursor.close()
      connection.close()


# remove wishlist

@app.delete("/remove/wishlist")
@limiter.limit("3/minute")

def remove_wishlist(request : Request , remove : List[WishlistItem] , token : str = Depends(verify_token)):
   try:
      connection = get_connection()
      cursor = connection.cursor()

      count = 0
      query = "delete from wishlists where user_id = %s and book_id = %s"
      for remo in remove:
         values = (token , remo.book_id)
         cursor.execute(query , values)
         if cursor.rowcount > 0:
            count += 1
      if count ==0:
         raise HTTPException(status_code=404 , detail= "not remove wishlist")
      connection.commit()
      return {"remove sucessfully remove count :  ": count}
   
   except Exception as e:
      connection.rollback()
      raise HTTPException(status_code=500 , detail=f"database error{str(e)}")
   finally:
      cursor.close()
      connection.close()


#  Implement a recommendation system based on past purchases or ratings.

@app.get("/Recommend/book")
@limiter.limit("3/minute")

def recommend_books(request : Request , token: str = Depends(verify_token)):
    try:
        connection = get_connection()
        cursor = connection.cursor(dictionary=True)

        query1 = "SELECT DISTINCT b.category FROM orders o, books b WHERE o.book_id = b.book_id AND o.user_id = %s"
        cursor.execute(query1, (token,))
        categories_result = cursor.fetchall()

        if categories_result == []:
            return {"message": "No purchases found to recommend books."}

        final_books = []

        for cat in categories_result:
            query2 = "SELECT DISTINCT book_id, title, author, category, price FROM books WHERE category = %s"
            cursor.execute(query2, (cat["category"],))  
            books_in_cat = cursor.fetchall()

            for book in books_in_cat:
                final_books.append(book)

        return {"recommended_books": final_books}

    except Exception as e:
        raise HTTPException(status_code=500, detail="database  error: " + str(e))
    finally:
        cursor.close()
        connection.close()



# Allow admins to generate reports on sales, stock, and user activity
# total sales

@app.get("/total/sales")
@limiter.limit("3/minute")

def total_sale(request : Request , token : str = Depends(verify_admin)):
   try:
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)
      query = "select count(*) as total_order , sum(total_price) as total_revenue from orders"
      cursor.execute(query)
      data = cursor.fetchone()
      return {"total sale" : data}
   except Exception as e:
      raise HTTPException(status_code=500, detail="database  error: " + str(e))
   finally:
      cursor.close()
      connection.close()

# stock

@app.get("/stock")
@limiter.limit("3/minute")

def total_stock(request : Request , token : str = Depends(verify_admin)):
   try:
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)
      query = "select book_id , title , author  , stock from books "
      cursor.execute(query)
      data = cursor.fetchall()
      return {"stock": data}
   except Exception as e:
      raise HTTPException(status_code=500, detail="database error: " + str(e))
   finally:
      cursor.close()
      connection.close()

# user activity 

@app.get("/report/user_activity")
@limiter.limit("3/minute")

def user_activity(request : Request , token : str = Depends(verify_admin)):
   try:
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)
      query = """select u.user_id , u.username , count(o.order_id) as total_order , 
                 sum(o.total_price) as total_spent 
                 from users as u
                 left join orders as o
                 on o.user_id = u.user_id
                 group by u.user_id , u.username"""
      cursor.execute(query)
      data = cursor.fetchall()
      return {"user activity report ": data}
   except Exception as e:
      raise HTTPException(status_code=500, detail="database error: " + str(e))
   finally:
      cursor.close()
      connection.close()


# smtp server for email 

smpt_server = "smtp.gmail.com"
port = 587
sender_email = "naveengusain0265@gmail.com"
app_password = "nqvkyyqdgqqjxjuf"

def send_email(recive_mail , subject , massage):
   try:
      msg = MIMEMultipart()
      msg["From"] = sender_email
      msg["To"] = recive_mail
      msg["Subject"] = subject
      msg.attach(MIMEText(massage , "plain"))

      server = smtplib.SMTP(smpt_server , port)
      server.starttls()
      server.login(sender_email , app_password)
      server.sendmail(sender_email , recive_mail , msg.as_string())
      return ("email sucessfully send")
   except Exception as e:
      raise HTTPException(status_code= 400 , detail= f"smtp error {str(e)}")
   finally:
      server.quit()

# email send for user

@app.get("/mail/send")
@limiter.limit("3/minute")

def post_email(request: Request , token : str = Depends(verify_admin)):
   try:
      connection = get_connection()
      cursor = connection.cursor(dictionary=True)
      query = """select u.email, o.status from users as u
                 join orders as o
                 on o.user_id = u.user_id """
      cursor.execute(query)
      data = cursor.fetchall()
      if not data:
         return ("no found order")

      for row in data:
         email = row["email"]
         status = row["status"]
         subject = "order status"
         massage = f"hello \n\n your order status is {status}"
         send_email(email , subject , massage)
      return {"massage": "email sent to all users"}
   
   except Exception as e:
      raise HTTPException(status_code=500, detail="database error: " + str(e))
   finally:
      cursor.close()
      connection.close()



