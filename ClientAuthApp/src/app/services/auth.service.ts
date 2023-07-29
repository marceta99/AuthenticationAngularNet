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
    localStorage.removeItem("token");
    console.log("Token deleted");
  }

  public loginWithGoogle(credentials: string): Observable<any>{
    const header = new HttpHeaders().set('Content-type', 'application/json');
    return this.httpClient.post(
      this.path + "LoginWithGoogle",
      JSON.stringify(credentials),
      { headers: header}
    );
  }
}
