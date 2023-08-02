import { HttpClient, HttpHeaderResponse, HttpHeaders } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { environment } from 'src/enviroments/enviroments';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private path = environment.apiUrl;

  constructor(private httpClient: HttpClient) { }

  public signOutExternal(){
    localStorage.removeItem("user");
  }

  public loginWithGoogle(credentials: string): Observable<any>{
    const header = new HttpHeaders().set('Content-type', 'application/json');
    return this.httpClient.post(
      this.path + "Auth/LoginWithGoogle",
      JSON.stringify(credentials),
      { headers: header}
    );
  }

  public getColors():Observable<any>{
    return this.httpClient.get(this.path + "Item/GetColorList",
    {withCredentials : true});
  }

  refreshToken(): Observable<any> {
    const header = new HttpHeaders().set('Content-type', 'application/json');
    return this.httpClient.get(this.path + "Auth/RefreshToken", { headers: header, withCredentials: true });
  }

  revokeToken(): Observable<any> {
    const header = new HttpHeaders().set('Content-type', 'application/json');
    return this.httpClient.delete(this.path + "Auth/RevokeToken/marcetic.mihailo99@gmail.com" , { headers: header, withCredentials: true });
  }
}
